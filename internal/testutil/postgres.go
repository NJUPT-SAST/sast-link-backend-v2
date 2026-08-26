// Package testutil provides integration-test infrastructure.
package testutil

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"sync"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// RequireProvider calls t.Fatal if the Docker provider is not healthy.
// Use this in TestMain or environment-guarded helpers for environments where
// skipped integration tests should surface as explicit failures.
func RequireProvider(t *testing.T) {
	t.Helper()
	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		t.Fatalf("Testcontainers Docker provider is required but unavailable: %v", err)
	}
	if err := provider.Health(context.Background()); err != nil {
		t.Fatalf("Testcontainers Docker health check failed: %v", err)
	}
}

// StartPostgres starts an isolated PostgreSQL 16 database and returns its URL.
func StartPostgres(t *testing.T) string {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx := context.Background()
	container, err := tcpostgres.Run(
		ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("sastlink_test"),
		tcpostgres.WithUsername("sastlink"),
		tcpostgres.WithPassword("sastlink"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
		),
	)
	if err != nil {
		t.Fatalf("start PostgreSQL container: %v", err)
	}

	t.Cleanup(func() {
		terminateErr := testcontainers.TerminateContainer(container)
		if terminateErr != nil {
			t.Errorf("terminate PostgreSQL container: %v", terminateErr)
		}
	})

	databaseURL, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("get PostgreSQL connection string: %v", err)
	}
	return databaseURL
}

// OpenSQL opens a pgx-backed database/sql connection to a test database.
func OpenSQL(t *testing.T, databaseURL string) *sql.DB {
	t.Helper()

	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open PostgreSQL SQL connection: %v", err)
	}
	if err := database.PingContext(context.Background()); err != nil {
		_ = database.Close()
		t.Fatalf("ping PostgreSQL SQL connection: %v", err)
	}
	return database
}

// OpenGORM opens a GORM connection to a disposable PostgreSQL test database.
func OpenGORM(t *testing.T, databaseURL string) *gorm.DB {
	t.Helper()

	database, err := gorm.Open(gormpostgres.Open(databaseURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("open GORM PostgreSQL connection: %v", err)
	}
	return database
}

// sharedPostgres is a process-wide PostgreSQL container shared by every call to
// SharedPostgresURL within one test binary. The container itself is started once
// per process (per go test invocation for a package); the testcontainers reaper
// removes it when the process exits, so no t.Cleanup is registered here.
var sharedPostgres struct {
	once sync.Once
	url  string  // base URL against the sastlink_test database, no per-test schema
	db   *sql.DB // admin connection used to create and drop per-test schemas
	err  error
}

// startSharedPostgres boots the shared container and its admin connection on
// first use. Later callers reuse both.
func startSharedPostgres() (string, *sql.DB, error) {
	sharedPostgres.once.Do(func() {
		ctx := context.Background()
		container, err := tcpostgres.Run(
			ctx,
			"postgres:16-alpine",
			tcpostgres.WithDatabase("sastlink_test"),
			tcpostgres.WithUsername("sastlink"),
			tcpostgres.WithPassword("sastlink"),
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
			),
		)
		if err != nil {
			sharedPostgres.err = fmt.Errorf("start shared PostgreSQL container: %w", err)
			return
		}
		databaseURL, err := container.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			sharedPostgres.err = fmt.Errorf("get shared PostgreSQL connection string: %w", err)
			return
		}
		db, err := sql.Open("pgx", databaseURL)
		if err != nil {
			sharedPostgres.err = fmt.Errorf("open shared PostgreSQL admin connection: %w", err)
			return
		}
		if err := db.PingContext(ctx); err != nil {
			sharedPostgres.err = fmt.Errorf("ping shared PostgreSQL admin connection: %w", err)
			return
		}
		sharedPostgres.url = databaseURL
		sharedPostgres.db = db
	})
	return sharedPostgres.url, sharedPostgres.db, sharedPostgres.err
}

// SharedPostgresURL starts a package-level PostgreSQL container on first call,
// creates a fresh isolated schema inside it for this test, and returns a
// connection URL whose search_path points at that schema. The schema is created
// and dropped by the shared admin connection, so each call returns a distinct
// schema and tests using this helper never see each other's rows — the same
// table names resolve to different physical tables. The schema is dropped when
// the test completes (DROP SCHEMA ... CASCADE), so a failed test leaves no
// residue behind the next one.
//
// Migrations and GORM connections opened against the returned URL both honor
// search_path, so running the full migration per test (as setupDatabase does)
// confines every object to the test's own schema. The expensive part — the
// container boot — happens once per process instead of once per test.
func SharedPostgresURL(t *testing.T) string {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)

	baseURL, admin, err := startSharedPostgres()
	if err != nil {
		t.Fatalf("shared PostgreSQL: %v", err)
	}
	if admin == nil {
		t.Fatal("shared PostgreSQL admin connection is nil")
	}

	schema := newTestSchemaName()
	if _, createErr := admin.ExecContext(context.Background(), fmt.Sprintf(`CREATE SCHEMA %q`, schema)); createErr != nil {
		t.Fatalf("create schema %q: %v", schema, createErr)
	}
	t.Cleanup(func() {
		if _, dropErr := admin.ExecContext(context.Background(), fmt.Sprintf(`DROP SCHEMA %q CASCADE`, schema)); dropErr != nil {
			t.Errorf("drop schema %q: %v", schema, dropErr)
		}
	})

	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse shared PostgreSQL URL: %v", err)
	}
	query := u.Query()
	query.Set("search_path", schema+",public")
	u.RawQuery = query.Encode()
	return u.String()
}

// newTestSchemaName returns a randomly named, PostgreSQL-safe schema name. The
// randomness keeps concurrent tests (same package, parallel run) from colliding.
func newTestSchemaName() string {
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// Only reachable if the OS entropy source is broken; the test suite
		// cannot proceed without it, so panicking is preferable to handing every
		// test the same schema.
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return "test_" + hex.EncodeToString(raw[:])
}
