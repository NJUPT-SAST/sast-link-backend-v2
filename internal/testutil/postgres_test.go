package testutil_test

import (
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
)

func TestStartPostgres(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })

	var version string
	if err := database.QueryRow("SHOW server_version").Scan(&version); err != nil {
		t.Fatalf("query PostgreSQL version: %v", err)
	}
	if version == "" {
		t.Fatal("PostgreSQL version is empty")
	}
}

func TestRequireProviderChecksDocker(t *testing.T) {
	testutil.RequireProvider(t)
}
