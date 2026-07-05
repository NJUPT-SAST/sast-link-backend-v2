package redis

import (
	"testing"
)

func TestNew(t *testing.T) {
	addr := "redis-test:6379"
	password := "secret"
	db := 2

	client, err := New(addr, password, db)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil redis client")
	}

	opts := client.Options()
	if opts.Addr != addr {
		t.Errorf("Addr = %q, want %q", opts.Addr, addr)
	}
	if opts.Password != password {
		t.Errorf("Password = %q, want %q", opts.Password, password)
	}
	if opts.DB != db {
		t.Errorf("DB = %d, want %d", opts.DB, db)
	}

	if err := Close(client); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}
