// Package migration constructs embedded SQL migrations for PostgreSQL.
package migration

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/NJUPT-SAST/sast-link-backend-v2/migrations"
)

// New creates a migration instance using embedded SQL and the pgx/v5 driver.
func New(databaseURL string) (*migrate.Migrate, error) {
	source, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("create migration source: %w", err)
	}

	migrationURL, err := toMigrationURL(databaseURL)
	if err != nil {
		return nil, err
	}
	instance, err := migrate.NewWithSourceInstance("iofs", source, migrationURL)
	if err != nil {
		return nil, fmt.Errorf("create migration instance: %w", err)
	}
	return instance, nil
}

// Current returns the applied migration version and dirty state.
func Current(databaseURL string) (uint, bool, error) {
	instance, err := New(databaseURL)
	if err != nil {
		return 0, false, err
	}
	defer func() { _, _ = instance.Close() }()

	version, dirty, err := instance.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read migration version: %w", err)
	}
	return version, dirty, nil
}

func toMigrationURL(databaseURL string) (string, error) {
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		return "", fmt.Errorf("parse PostgreSQL URL: %w", err)
	}
	switch parsed.Scheme {
	case "postgres", "postgresql", "pgx5":
		parsed.Scheme = "pgx5"
	default:
		return "", fmt.Errorf("unsupported PostgreSQL URL scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" || strings.Trim(parsed.Path, "/") == "" {
		return "", fmt.Errorf("PostgreSQL URL must contain host and database name")
	}
	query := parsed.Query()
	query.Set("x-multi-statement", "true")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
