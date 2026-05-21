package infra

import (
	"context"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
)

func TestNewDB_InvalidDSN(t *testing.T) {
	cfg := config.DBConfig{
		Host:     "invalid-host",
		Port:     5432,
		User:     "test",
		Password: "test",
		Database: "test",
		SSLMode:  "disable",
	}
	// Connection should fail with invalid host
	_, err := NewDB(&cfg)
	if err == nil {
		t.Fatal("database connection succeeded unexpectedly; may have local postgres")
	}
}

func TestNewDB_DSNFormat(t *testing.T) {
	cfg := config.DBConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "sastlink",
		Password: "secret",
		Database: "sastlink",
		SSLMode:  "disable",
	}
	dsn := cfg.DSN()
	want := "host=localhost port=5432 user=sastlink password=secret dbname=sastlink sslmode=disable"
	if dsn != want {
		t.Errorf("DSN = %q, want %q", dsn, want)
	}
}

func TestHealthCheckDB_NilDB(t *testing.T) {
	ctx := context.Background()
	err := HealthCheckDB(ctx, nil)
	if err == nil {
		t.Error("HealthCheckDB(nil) expected error")
	}
}
