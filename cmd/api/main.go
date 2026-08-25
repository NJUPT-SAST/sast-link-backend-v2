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
	_ "go.uber.org/automaxprocs" // calibrate GOMAXPROCS to the container's cgroup CPU quota

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/db"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/health"
	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/adminhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/alumnihandler"
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
	// automaxprocs sets GOMAXPROCS from the cgroup CPU quota (1 on the all-in-one
	// bench); log the effective value so a measurement session can prove it is
	// running single-core rather than spilling onto the host.
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

	// Release mode suppresses gin's debug-mode per-request overhead and startup
	// noise (route printing, panic stack dumps); debug tracing is not useful in a
	// service whose request path is already pprof-instrumented.
	if cfg.AppEnv != "development" {
		gin.SetMode(gin.ReleaseMode)
	}
	router, err := web.NewRouter(cfg.CORSAllowedOrigins, cfg.TrustedProxies, cfg.HSTSMaxAge)
	if err != nil {
		return fmt.Errorf("create router: %w", err)
	}
	// pprof is fail-closed: exposed only in an explicit development environment
	// or when PPROF_ENABLED is set. The old `!= "production"` gate left it open
	// whenever APP_ENV was unset (the default), letting an unauthenticated caller
	// trigger CPU sampling or dump goroutine stacks on a production box that
	// merely forgot the env var.
	if cfg.AppEnv == "development" || cfg.EnablePprof {
		registerProfiling(router)
	}
	health.New(map[string]func() error{
		"db":    func() error { return pingDB(database) },
		"redis": func() error { return pingRedis(rdb) },
	}).Register(router)
	// The /user group authenticates through RequireUserAuth, not RequireAuth: it is
	// the surface a registered client may reach on a user's own behalf,
	// within the user scopes that token holds. The strict internal-client pin stays
	// on every group that does not opt in.
	sessionhandler.RegisterRoutes(router, runtime.Handler, sessionhandler.Gates{
		RequireAuth:       runtime.Auth.RequireUserAuth(),
		RequireReadScope:  runtime.Auth.RequireDelegatedScope(sessionhandler.ReadScopes...),
		RequireWriteScope: runtime.Auth.RequireDelegatedScope(sessionhandler.WriteScopes...),
		// Logout admits an expired access token so a stale tab can end its
		// session; RequireUserLogoutAuth applies the same /user scope policy.
		RequireLogoutAuth: runtime.Auth.RequireUserLogoutAuth(),
	})
	oauthhandler.RegisterRoutes(router, runtime.OAuth, runtime.Auth.RequireAuth())
	oauthloginhandler.RegisterRoutes(router, runtime.OAuthLogin, runtime.Auth.RequireAuth())
	// The admin group authenticates through RequireAdminAuth, not RequireAuth: it is
	// the one surface a admin-scoped token may reach, and only within the
	// scopes that token holds. Every other group keeps the strict internal-client pin.
	adminhandler.RegisterRoutes(router, runtime.Admin, adminhandler.Gates{
		RequireAuth:       runtime.Auth.RequireAdminAuth(),
		RequireReadScope:  runtime.Auth.RequireDelegatedScope(adminhandler.ReadScopes...),
		RequireWriteScope: runtime.Auth.RequireDelegatedScope(adminhandler.WriteScopes...),
		RequireAdmin:      runtime.Auth.RequireRole(adminhandler.AdminRole),
		RequireReader:     runtime.Auth.RequireRole(adminhandler.ReaderRoles...),
	})
	// The account-request routes mount their own /admin group behind the same gates.
	// POST /alumni-requests is deliberately outside it: the applicants are people who
	// have no account by definition, so its protection is the service's Turnstile
	// check and rate limiter rather than a middleware.
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
