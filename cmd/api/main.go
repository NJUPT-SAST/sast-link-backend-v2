// Command api runs the SAST Link v2 HTTP API server.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/joho/godotenv"
	goredis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/db"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/health"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web"
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

	setupLogger(cfg.LogLevel)

	database, err := db.Open(cfg.PostgresDSN())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close(database)

	rdb, err := redis.New(cfg.RedisAddr(), cfg.RedisPassword, cfg.RedisDB)
	if err != nil {
		return fmt.Errorf("open redis: %w", err)
	}
	defer redis.Close(rdb)

	router := web.NewRouter()
	health.New(map[string]func() error{
		"db":    func() error { return pingDB(database) },
		"redis": func() error { return pingRedis(rdb) },
	}).Register(router)

	slog.Info("server starting", slog.String("port", cfg.AppPort))
	return router.Run(":" + cfg.AppPort)
}

func setupLogger(level string) {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{Level: slogLevel},
	)))
}

func pingDB(database *gorm.DB) error {
	sqlDB, err := database.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

func pingRedis(client *goredis.Client) error {
	return client.Ping(context.Background()).Err()
}
