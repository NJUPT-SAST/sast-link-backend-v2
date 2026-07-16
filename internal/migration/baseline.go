package migration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var requiredTables = []string{
	"user", "profile", "identities", "oauth_clients",
	"oauth_authorizations", "oauth_access_tokens",
	"oauth_refresh_tokens", "audit_logs",
}

const tableExistsQuery = `SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_tables
  WHERE schemaname = 'public' AND tablename = $1
)`

// BaselineV1 records V001 for an existing, complete V001 schema without running migration DDL.
func BaselineV1(ctx context.Context, databaseURL string) error {
	if err := preflightV1Schema(ctx, databaseURL); err != nil {
		return err
	}

	instance, err := New(databaseURL)
	if err != nil {
		return err
	}
	defer func() { _, _ = instance.Close() }()

	version, dirty, err := instance.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		if err := instance.Force(1); err != nil {
			return fmt.Errorf("record V001 baseline: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read migration version: %w", err)
	}
	if version != 1 {
		return fmt.Errorf("cannot baseline V001: migration version %d is not 1", version)
	}
	if dirty {
		return errors.New("cannot baseline V001: migration version 1 is dirty")
	}
	return nil
}

func preflightV1Schema(ctx context.Context, databaseURL string) error {
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open PostgreSQL database: %w", err)
	}
	defer func() { _ = database.Close() }()

	if err := database.PingContext(ctx); err != nil {
		return fmt.Errorf("ping PostgreSQL database: %w", err)
	}
	if err := requireCatalogObjects(ctx, database, tableExistsQuery, "table", requiredTables); err != nil {
		return err
	}
	if err := requireV1Enums(ctx, database); err != nil {
		return err
	}
	if err := requireV1Columns(ctx, database); err != nil {
		return err
	}
	if err := requireV1Defaults(ctx, database); err != nil {
		return err
	}
	if err := requireV1Constraints(ctx, database); err != nil {
		return err
	}
	if err := requireV1Indexes(ctx, database); err != nil {
		return err
	}
	if err := requireV1Functions(ctx, database); err != nil {
		return err
	}
	if err := requireV1Triggers(ctx, database); err != nil {
		return err
	}
	return nil
}

func requireCatalogObjects(
	ctx context.Context,
	database *sql.DB,
	query string,
	objectKind string,
	names []string,
) error {
	for _, name := range names {
		var exists bool
		if err := database.QueryRowContext(ctx, query, name).Scan(&exists); err != nil {
			return fmt.Errorf("check required %s %q: %w", objectKind, name, err)
		}
		if !exists {
			return fmt.Errorf("missing required %s %q", objectKind, name)
		}
	}
	return nil
}
