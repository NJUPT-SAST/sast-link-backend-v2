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

var requiredTypes = []string{
	"user_role_enum", "state_enum", "email_enum", "department_enum",
	"login_method_enum", "client_enum", "college_enum",
}

type requiredTrigger struct {
	name   string
	schema string
	table  string
}

var requiredTriggers = []requiredTrigger{
	{name: "trg_user_updated_at", schema: "public", table: "user"},
	{name: "trg_profile_updated_at", schema: "public", table: "profile"},
	{name: "trg_identities_updated_at", schema: "public", table: "identities"},
	{name: "trg_oauth_clients_updated_at", schema: "public", table: "oauth_clients"},
	{name: "trg_identities_other_mail_limit", schema: "public", table: "identities"},
	{name: "trg_user_email_domain", schema: "public", table: "user"},
}

const tableExistsQuery = `SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_tables
  WHERE schemaname = 'public' AND tablename = $1
)`

const typeExistsQuery = `SELECT EXISTS (
  SELECT 1
  FROM pg_catalog.pg_type typ
  JOIN pg_catalog.pg_namespace ns ON ns.oid = typ.typnamespace
  WHERE ns.nspname = 'public' AND typ.typname = $1
)`

const triggerExistsQuery = `SELECT EXISTS (
  SELECT 1
  FROM pg_catalog.pg_trigger trigger
  JOIN pg_catalog.pg_class relation ON relation.oid = trigger.tgrelid
  JOIN pg_catalog.pg_namespace schema ON schema.oid = relation.relnamespace
  WHERE NOT trigger.tgisinternal
    AND trigger.tgname = $1
    AND relation.relname = $2
    AND schema.nspname = $3
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
	if err := requireCatalogObjects(ctx, database, typeExistsQuery, "type", requiredTypes); err != nil {
		return err
	}
	if err := requireRequiredTriggers(ctx, database); err != nil {
		return err
	}
	return nil
}

func requireRequiredTriggers(ctx context.Context, database *sql.DB) error {
	for _, trigger := range requiredTriggers {
		var exists bool
		if err := database.QueryRowContext(
			ctx,
			triggerExistsQuery,
			trigger.name,
			trigger.table,
			trigger.schema,
		).Scan(&exists); err != nil {
			return fmt.Errorf(
				"check required trigger %q on table %q.%q: %w",
				trigger.name,
				trigger.schema,
				trigger.table,
				err,
			)
		}
		if !exists {
			return fmt.Errorf(
				"missing required trigger %q on table %q.%q",
				trigger.name,
				trigger.schema,
				trigger.table,
			)
		}
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
