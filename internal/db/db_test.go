package db_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver for sql.Open
	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/db"
)

// Open is exercised through its error paths only: gorm.Open pings the database
// by default, so a well-formed DSN would dial a real PostgreSQL and that belongs
// to the Testcontainers integration suite, not to a unit test. A syntactically
// invalid DSN is rejected by pgx's ParseConfig before any network is touched.
func TestOpenRejectsMalformedDSN(t *testing.T) {
	cases := []struct {
		name string
		dsn  string
	}{
		{name: "not a url nor keyword/value", dsn: "://"},
		{name: "nul byte in dsn", dsn: "\x00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := db.Open(tc.dsn)
			if err == nil {
				t.Fatal("Open: expected error for malformed dsn")
			}
			if got != nil {
				t.Error("Open: returned a non-nil db alongside an error")
			}
			var parseErr *pgconn.ParseConfigError
			if !errors.As(err, &parseErr) {
				t.Fatalf("Open(%q): error = %v, want a pgconn.ParseConfigError", tc.dsn, err)
			}
			if !strings.Contains(err.Error(), "open database: ") {
				t.Errorf("Open(%q): error %q does not carry the wrapping context", tc.dsn, err)
			}
		})
	}
}

// Close walks the underlying *sql.DB obtained from the GORM handle. The handle
// is assembled directly because Open needs a live database; the contract being
// pinned is that Close releases the pool it was handed.
func TestCloseReleasesUnderlyingPool(t *testing.T) {
	sqlDB, err := sql.Open("pgx", "host=127.0.0.1 port=5432") // lazy: no connection yet
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	gormDB := &gorm.DB{Config: &gorm.Config{ConnPool: sqlDB}}

	if err := db.Close(gormDB); err != nil {
		t.Fatalf("Close: unexpected error: %v", err)
	}
	if err := sqlDB.PingContext(context.Background()); err == nil {
		t.Error("Close: underlying pool is still usable after close")
	} else if !strings.Contains(err.Error(), "closed") {
		t.Errorf("Close: ping after close error = %v, want a closed-pool error", err)
	}
}

func TestCloseRejectsHandleWithoutPool(t *testing.T) {
	gormDB := &gorm.DB{Config: &gorm.Config{}}

	err := db.Close(gormDB)
	if err == nil {
		t.Fatal("Close: expected error for a handle without a *sql.DB pool")
	}
	if !errors.Is(err, gorm.ErrInvalidDB) {
		t.Errorf("Close: error = %v, want %v", err, gorm.ErrInvalidDB)
	}
}
