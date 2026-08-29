package testutil_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
)

func TestStartPostgres(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })

	var version string
	if err := database.QueryRowContext(context.Background(), "SHOW server_version").Scan(&version); err != nil {
		t.Fatalf("query PostgreSQL version: %v", err)
	}
	if version == "" {
		t.Fatal("PostgreSQL version is empty")
	}
}

func TestRequireProviderChecksDocker(t *testing.T) {
	testutil.RequireProvider(t)
}

func TestSharedPostgresURLIsolation(t *testing.T) {
	urlA := testutil.SharedPostgresURL(t)
	urlB := testutil.SharedPostgresURL(t)
	if urlA == urlB {
		t.Fatal("SharedPostgresURL returned the same URL twice")
	}

	dbA := testutil.OpenSQL(t, urlA)
	t.Cleanup(func() { _ = dbA.Close() })
	dbB := testutil.OpenSQL(t, urlB)
	t.Cleanup(func() { _ = dbB.Close() })

	probe := func(db *sql.DB, marker string) {
		t.Helper()
		if _, err := db.ExecContext(context.Background(), `CREATE TABLE isolation_probe (marker text)`); err != nil {
			t.Fatalf("create isolation_probe: %v", err)
		}
		if _, err := db.ExecContext(context.Background(), `INSERT INTO isolation_probe VALUES ($1)`, marker); err != nil {
			t.Fatalf("insert marker: %v", err)
		}
	}
	probe(dbA, "from-a")
	probe(dbB, "from-b")

	var markerA, markerB string
	if err := dbA.QueryRowContext(context.Background(), `SELECT marker FROM isolation_probe`).Scan(&markerA); err != nil {
		t.Fatalf("read A: %v", err)
	}
	if err := dbB.QueryRowContext(context.Background(), `SELECT marker FROM isolation_probe`).Scan(&markerB); err != nil {
		t.Fatalf("read B: %v", err)
	}
	if markerA != "from-a" || markerB != "from-b" {
		t.Fatalf("isolation broken: A=%q B=%q", markerA, markerB)
	}

	var schemaA, schemaB string
	if err := dbA.QueryRowContext(context.Background(), `SELECT current_schema()`).Scan(&schemaA); err != nil {
		t.Fatalf("read current_schema A: %v", err)
	}
	if err := dbB.QueryRowContext(context.Background(), `SELECT current_schema()`).Scan(&schemaB); err != nil {
		t.Fatalf("read current_schema B: %v", err)
	}
	if schemaA == schemaB {
		t.Fatalf("both connections share schema %q", schemaA)
	}
}
