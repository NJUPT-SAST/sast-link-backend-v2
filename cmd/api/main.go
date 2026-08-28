// Command api runs the SAST Link v2 HTTP API server.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	_ "go.uber.org/automaxprocs" // calibrate GOMAXPROCS to the container's cgroup CPU quota

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/db"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/health"
	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/adminhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/alumnihandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/oauthhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/oauthloginhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/sessionhandler"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if os.Getenv("APP_ENV") != "production" {
		_ = godotenv.Load()
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if validateErr := cfg.ValidateAPIAuth(); validateErr != nil {
		return fmt.Errorf("validate API auth config: %w", validateErr)
	}

	setupLogger(cfg.LogLevel)
	// automaxprocs calibrates GOMAXPROCS from the container's cgroup CPU quota; log the effective value.
	slog.Info("effective GOMAXPROCS", slog.Int("gomaxprocs", runtime.GOMAXPROCS(0)))

	database, err := db.Open(cfg.PostgresDSN())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close(database) }()

	rdb, err := internalredis.New(cfg.RedisAddr(), cfg.RedisSecret, cfg.RedisDB)
	if err != nil {
		return fmt.Errorf("open redis: %w", err)
	}
	defer func() { _ = internalredis.Close(rdb) }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runtime, err := buildSessionRuntime(ctx, cfg, database, rdb)
	if err != nil {
		return err
	}

	// Release mode suppresses gin's debug-mode per-request overhead and startup noise.
	if cfg.AppEnv != "development" {
		gin.SetMode(gin.ReleaseMode)
	}
	router, err := web.NewRouter(cfg.CORSAllowedOrigins, cfg.TrustedProxies, cfg.HSTSMaxAge)
	if err != nil {
		return fmt.Errorf("create router: %w", err)
	}
	// Application metrics: the middleware observes every request (registered
	// outermost, so it wraps the other middleware too) and /metrics exposes the
	// default Prometheus registry. Like /health it is an anonymous scrape surface,
	// deliberately outside every auth gate.
	router.Use(middleware.Metrics())
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))
	// pprof is fail-closed: only an explicit development environment or PPROF_ENABLED enables it.
	if cfg.AppEnv == "development" || cfg.EnablePprof {
		registerProfiling(router)
	}
	health.New(map[string]func() error{
		"db":    func() error { return pingDB(database) },
		"redis": func() error { return pingRedis(rdb) },
	}).Register(router)
	// The /user group authenticates through RequireUserAuth so a registered client
	// can act on a user's own behalf within the scopes its token holds.
	sessionhandler.RegisterRoutes(router, runtime.Handler, sessionhandler.Gates{
		RequireAuth:       runtime.Auth.RequireUserAuth(),
		RequireReadScope:  runtime.Auth.RequireDelegatedScope(sessionhandler.ReadScopes...),
		RequireWriteScope: runtime.Auth.RequireDelegatedScope(sessionhandler.WriteScopes...),
		// Logout admits an expired access token so a stale tab can still end its session.
		RequireLogoutAuth: runtime.Auth.RequireUserLogoutAuth(),
	})
	oauthhandler.RegisterRoutes(router, runtime.OAuth, runtime.Auth.RequireAuth())
	oauthloginhandler.RegisterRoutes(router, runtime.OAuthLogin, oauthloginhandler.Gates{
		RequireAuth:       runtime.Auth.RequireAuth(),
		RequireWriteScope: runtime.Auth.RequireDelegatedScope(oauthloginhandler.WriteScopes...),
	})
	// The admin group authenticates through RequireAdminAuth, the only surface an
	// admin-scoped token may reach within the scopes it holds.
	adminhandler.RegisterRoutes(router, runtime.Admin, adminhandler.Gates{
		RequireAuth:       runtime.Auth.RequireAdminAuth(),
		RequireReadScope:  runtime.Auth.RequireDelegatedScope(adminhandler.ReadScopes...),
		RequireWriteScope: runtime.Auth.RequireDelegatedScope(adminhandler.WriteScopes...),
		RequireAdmin:      runtime.Auth.RequireRole(adminhandler.AdminRole),
		RequireReader:     runtime.Auth.RequireRole(adminhandler.ReaderRoles...),
	})
	// The account-request routes mount their own /admin group behind the same gates.
	// POST /alumni-requests stays outside it: applicants have no account, so the
	// Turnstile check and rate limiter protect it rather than a middleware.
	alumnihandler.RegisterRoutes(router, runtime.Alumni, alumnihandler.Gates{
		RequireAuth:       runtime.Auth.RequireAdminAuth(),
		RequireReadScope:  runtime.Auth.RequireDelegatedScope(alumnihandler.ReadScopes...),
		RequireWriteScope: runtime.Auth.RequireDelegatedScope(alumnihandler.WriteScopes...),
		RequireAdmin:      runtime.Auth.RequireRole(alumnihandler.AdminRole),
		RequireReader:     runtime.Auth.RequireRole(alumnihandler.ReaderRoles...),
	})

	slog.Info("server starting", slog.String("port", cfg.AppPort))
	return serve(ctx, ":"+cfg.AppPort, router, runtime.Workers)
}
