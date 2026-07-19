// Package testutil provides integration-test infrastructure.
package testutil

import (
	"context"
	"database/sql"
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
