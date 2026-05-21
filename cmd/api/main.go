// Package main is the entry point for the SAST Link API server.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/infra"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/pkg/response"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	infra.InitLogger(cfg.App.LogLevel)
	slog.Info("starting sast-link-backend-v2", "env", cfg.App.Env, "port", cfg.App.Port)

	db, err := infra.NewDB(&cfg.DB)
	if err != nil {
		slog.Error("connect db", "error", err)
		os.Exit(1)
	}

	redisClient, err := infra.NewRedis(&cfg.Redis)
	if err != nil {
		slog.Error("connect redis", "error", err)
		os.Exit(1)
	}

	if cfg.App.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())
	if cfg.App.Env == "production" {
		if err := r.SetTrustedProxies([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1"}); err != nil {
			slog.Error("set trusted proxies", "error", err)
			os.Exit(1)
		}
	}

	defer func() {
		if err := redisClient.Close(); err != nil {
			slog.Error("close redis", "error", err)
		}
	}()

	_ = db
	_ = redisClient

	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	r.GET("/health", func(c *gin.Context) {
		checks := map[string]string{
			"database": "ok",
			"redis":    "ok",
		}
		if err := infra.HealthCheckDB(c.Request.Context(), db); err != nil {
			checks["database"] = "fail"
			slog.Warn("health check db failed", "error", err)
		}
		if err := redisClient.Ping(context.Background()).Err(); err != nil {
			checks["redis"] = "fail"
			slog.Warn("health check redis failed", "error", err)
		}

		status := http.StatusOK
		for _, v := range checks {
			if v != "ok" {
				status = http.StatusServiceUnavailable
				break
			}
		}

		c.JSON(status, gin.H{
			"status":    "ok",
			"version":   "1.0.0",
			"checks":    checks,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	})

	r.NoRoute(func(c *gin.Context) {
		response.ErrWithStatus(c, http.StatusNotFound, domain.ErrInternal, "not found")
	})

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.App.Port),
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server listen", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown", "error", err)
	}
	slog.Info("server exited")
}
