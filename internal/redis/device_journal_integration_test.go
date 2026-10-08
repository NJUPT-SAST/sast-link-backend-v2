package redis

import (
	"context"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/shared"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
)

func TestDeviceJournalCapacityRefusesBeforeMutation(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	keys := NewKeys("capacity")
	store := Store{Client: client, Keys: keys}
	now := time.Now()
	if _, err := store.RegisterDevice(ctx, 1, "old", "ua", "ip", now, time.Hour, 1); err != nil {
		t.Fatal(err)
	}
	entries := make([]goredis.Z, 10000)
	for i := range entries {
		entries[i] = goredis.Z{Score: float64(i), Member: i}
	}
	if err := client.ZAdd(ctx, keys.join("{dev}", "pending_evictions"), entries...).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterDevice(ctx, 1, "new", "ua", "ip", now, time.Hour, 1, shared.DeviceOperation{TokenHash: "proof", ExpiresAt: now.Add(time.Hour)}); err == nil {
		t.Fatal("full journal accepted mutation")
	}
	devices, err := store.ListDevices(ctx, 1)
	if err != nil || len(devices) != 1 || devices[0].DeviceID != "old" {
		t.Fatalf("state changed at capacity: %v %v", devices, err)
	}
}

func TestTouchDeviceJournalAndIdempotentReplay(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	keys := NewKeys("touch-journal")
	store := Store{Client: client, Keys: keys}
	now := time.Now()
	if _, err := store.RegisterDevice(ctx, 1, "old", "ua", "ip", now, time.Hour, 1); err != nil {
		t.Fatal(err)
	}
	scriptKeys := []string{keys.Devices(1), keys.Device("new"), keys.deviceHashKeyPrefix(), keys.join("{dev}", "operation", "fixture"), keys.join("{dev}", "pending_evictions")}
	args := []any{"new", now.Add(time.Second).UTC().Format(time.RFC3339), 3600, "ua", "ip", now.Add(time.Second).UnixMilli(), 1, "committed-proof", 1, now.Add(time.Hour).Unix(), "new", "fixture"}
	for range 2 {
		result, err := evalScript(ctx, client, touchDeviceScript, scriptKeys, args...).Slice()
		if err != nil || len(result) != 2 || result[1] != "old" {
			t.Fatalf("replay result=%v %v", result, err)
		}
	}
	// A brand-new Store instance models a restarted worker; pending work does not
	// depend on process memory or on the short-lived operation result cache.
	client.Del(ctx, scriptKeys[3])
	restarted := Store{Client: client, Keys: keys}
	pending, err := restarted.PendingDeviceEvictions(ctx, 0, 100)
	if err != nil || len(pending) != 1 || pending[0].TokenHash != "committed-proof" || pending[0].Evicted != "old" {
		t.Fatalf("pending=%v error=%v", pending, err)
	}
	if ttl, err := client.TTL(ctx, scriptKeys[4]).Result(); err != nil || ttl != -1 {
		t.Fatalf("journal must survive until ack: ttl=%v error=%v", ttl, err)
	}
}
