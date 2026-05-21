package infra

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func setupMiniredis(t *testing.T) (rdb *redis.Client, cleanup func()) {
	s := miniredis.RunT(t)
	rdb = redis.NewClient(&redis.Options{Addr: s.Addr()})
	return rdb, func() {
		_ = rdb.Close()
		s.Close()
	}
}

func TestRedisIdempotencyStore_Get_NotFound(t *testing.T) {
	rdb, cleanup := setupMiniredis(t)
	defer cleanup()

	store := NewRedisIdempotencyStore(rdb)
	record, err := store.Get(context.Background(), "non-existent-key")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if record != nil {
		t.Error("Get() = record, want nil")
	}
}

func TestRedisIdempotencyStore_SetAndGet(t *testing.T) {
	rdb, cleanup := setupMiniredis(t)
	defer cleanup()

	store := NewRedisIdempotencyStore(rdb)
	record := &IdempotencyRecord{
		StatusCode: 200,
		Body:       json.RawMessage(`{"success":true}`),
		CreatedAt:  time.Now(),
	}

	if err := store.Set(context.Background(), "test-key", record, time.Hour); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, err := store.Get(context.Background(), "test-key")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got == nil {
		t.Fatal("Get() = nil, want record")
	}
	if got.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", got.StatusCode)
	}
}

func TestRedisIdempotencyStore_Set_DefaultTTL(t *testing.T) {
	rdb, cleanup := setupMiniredis(t)
	defer cleanup()

	store := NewRedisIdempotencyStore(rdb)
	record := &IdempotencyRecord{
		StatusCode: 200,
		Body:       json.RawMessage(`{}`),
		CreatedAt:  time.Now(),
	}

	if err := store.Set(context.Background(), "default-ttl-key", record, 0); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	ttl := rdb.TTL(context.Background(), "sastlink:idempotency:default-ttl-key").Val()
	if ttl < 23*time.Hour || ttl > 24*time.Hour {
		t.Errorf("TTL = %v, want ~24h", ttl)
	}
}

func TestRedisIdempotencyStore_Get_RedisError(t *testing.T) {
	rdb, cleanup := setupMiniredis(t)
	defer cleanup()

	store := NewRedisIdempotencyStore(rdb)
	cleanup() // close redis to force error

	_, err := store.Get(context.Background(), "any-key")
	if err == nil {
		t.Error("Get() expected error after redis close")
	}
}
