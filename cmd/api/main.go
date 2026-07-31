// Command api runs the SAST Link v2 HTTP API server.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/db"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/health"
	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/adminhandler"
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

	database, err := db.Open(cfg.PostgresDSN())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close(database) }()

	rdb, err := internalredis.New(cfg.RedisAddr(), cfg.RedisPassword, cfg.RedisDB)
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

	router, err := web.NewRouter(cfg.CORSAllowedOrigins, cfg.TrustedProxies, cfg.HSTSMaxAge)
	if err != nil {
		return fmt.Errorf("create router: %w", err)
	}
	health.New(map[string]func() error{
		"db":    func() error { return pingDB(database) },
		"redis": func() error { return pingRedis(rdb) },
	}).Register(router)
	sessionhandler.RegisterRoutes(router, runtime.Handler, runtime.Auth.RequireAuth())
	oauthhandler.RegisterRoutes(router, runtime.OAuth, runtime.Auth.RequireAuth())
	oauthloginhandler.RegisterRoutes(router, runtime.OAuthLogin, runtime.Auth.RequireAuth())
	adminhandler.RegisterRoutes(router, runtime.Admin,
		runtime.Auth.RequireAuth(),
		runtime.Auth.RequireRole(adminhandler.AdminRole),
		runtime.Auth.RequireRole(adminhandler.ReaderRoles...))

	slog.Info("server starting", slog.String("port", cfg.AppPort))
	return serve(ctx, ":"+cfg.AppPort, router, runtime.Workers)
}
