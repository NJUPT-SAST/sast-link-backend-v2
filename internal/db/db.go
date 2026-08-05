// Package db provides a GORM connection to PostgreSQL.
package db

import (
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// maxOpenConns caps the GORM pool. PostgreSQL's default max_connections is 100
// and this API runs on small instances, so an unbounded pool exhausts the server
// (SQLSTATE 53300 "too many clients") under load well before CPU or memory do.
// A 1-core box cannot drive more than a handful of concurrently-active queries
// (the classic 2×cores + spindles bound is ~3), so 10 open connections leave
// ample headroom without each PG backend's memory and lock overhead. Requests
// queue at the pool instead of opening a fresh connection and failing.
const maxOpenConns = 10

// Open returns a GORM connection using the provided PostgreSQL DSN.
// It returns an error if the dialect cannot be initialized.
func Open(dsn string) (*gorm.DB, error) {
	// PrepareStmt caches the hot queries' prepared statements client-side, saving
	// a protocol round trip and PG re-planning on every login/auth-state/profile
	// call, whose SQL text is stable. MaxSize/TTL bound the cache so it cannot
	// grow without limit.
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		PrepareStmt:        true,
		PrepareStmtMaxSize: 128,
		PrepareStmtTTL:     5 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get underlying db: %w", err)
	}
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(3)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	return db, nil
}

// Close closes the underlying *sql.DB of a GORM connection.
func Close(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("get underlying db: %w", err)
	}
	if err := sqlDB.Close(); err != nil {
		return fmt.Errorf("close database: %w", err)
	}
	return nil
}
