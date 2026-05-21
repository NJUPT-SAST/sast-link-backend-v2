// Package infra provides infrastructure concerns: database, Redis, logging, and idempotency.
package infra

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
)

// NewDB initializes a PostgreSQL connection via GORM.
func NewDB(cfg *config.DBConfig) (*gorm.DB, error) {
	logLevel := logger.Silent
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		logLevel = logger.Info
	}

	db, err := gorm.Open(postgres.Open(cfg.DSN()), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql db: %w", err)
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	return db, nil
}

// HealthCheckDB pings the database with a timeout.
func HealthCheckDB(ctx context.Context, db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("db is nil")
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return sqlDB.PingContext(ctx)
}
