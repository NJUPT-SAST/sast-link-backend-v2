package sessionredis

import (
	"context"
	"testing"
	"time"

	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
)

func newTestStore(t *testing.T) internalredis.Store {
	t.Helper()
	client := testutil.StartRedis(t)
	return internalredis.Store{Client: client, Keys: internalredis.NewKeys("sastlink:test")}
}

func TestEndpointLimiterAllowMapsDecision(t *testing.T) {
	store := newTestStore(t)
	limiter := EndpointLimiter{Limiter: internalredis.FixedWindowLimiter{
		Client: store.Client,
		Keys:   store.Keys,
		Limit:  2,
		Window: time.Minute,
	}}
	ctx := context.Background()

	for attempt := 1; attempt <= 2; attempt++ {
		result, err := limiter.Allow(ctx, "login", "127.0.0.1")
		if err != nil || !result.Allowed {
			t.Fatalf("attempt %d: result=%+v err=%v, want allowed", attempt, result, err)
		}
	}
	result, err := limiter.Allow(ctx, "login", "127.0.0.1")
	if err != nil || result.Allowed || result.RetryAfter <= 0 {
		t.Fatalf("third attempt result=%+v err=%v, want denied with retry-after", result, err)
	}
}

func TestLoginFailureStoreLockLifecycle(t *testing.T) {
	failures := LoginFailureStore{Store: newTestStore(t), Limit: 3, Window: 15 * time.Minute}
	ctx := context.Background()
	const key = "user@njupt.edu.cn"

	locked, _, err := failures.IsLocked(ctx, key)
	if err != nil || locked {
		t.Fatalf("initial IsLocked=%v err=%v, want unlocked", locked, err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		result, recordErr := failures.RecordFailure(ctx, key)
		if recordErr != nil {
			t.Fatalf("record failure %d: %v", attempt, recordErr)
		}
		if wantLocked := attempt == 3; result.Locked != wantLocked {
			t.Fatalf("failure %d locked=%v, want %v", attempt, result.Locked, wantLocked)
		}
	}
	locked, retryAfter, err := failures.IsLocked(ctx, key)
	if err != nil || !locked || retryAfter <= 0 {
		t.Fatalf("IsLocked=%v retry=%v err=%v, want locked with TTL", locked, retryAfter, err)
	}
	if resetErr := failures.Reset(ctx, key); resetErr != nil {
		t.Fatalf("reset failures: %v", resetErr)
	}
	locked, _, err = failures.IsLocked(ctx, key)
	if err != nil || locked {
		t.Fatalf("post-reset IsLocked=%v err=%v, want unlocked", locked, err)
	}
}

func TestBlacklistStoreDeleteAuthStates(t *testing.T) {
	blacklist := BlacklistStore{Store: newTestStore(t)}
	ctx := context.Background()

	// DeleteAuthStates is the revocation delivery: it removes cached auth-state
	// entries. Deleting keys that do not exist is a no-op, not an error; the
	// put/delete semantics live in the redis store integration tests.
	if err := blacklist.DeleteAuthStates(ctx, []string{"jti-42", "jti-43"}); err != nil {
		t.Fatalf("DeleteAuthStates: %v", err)
	}
}

func TestDeviceStoreRoundTrip(t *testing.T) {
	devices := DeviceStore{Store: newTestStore(t)}
	ctx := context.Background()
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	if _, err := devices.RegisterDevice(ctx, 42, "family-1", "browser/5", "10.0.0.1", now); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	owned, err := devices.DeviceOwnedBy(ctx, 42, "family-1")
	if err != nil || !owned {
		t.Fatalf("DeviceOwnedBy=%v err=%v, want owned", owned, err)
	}
	owned, err = devices.DeviceOwnedBy(ctx, 7, "family-1")
	if err != nil || owned {
		t.Fatalf("cross-user DeviceOwnedBy=%v err=%v, want not owned", owned, err)
	}

	later := now.Add(time.Minute)
	if _, touchErr := devices.TouchDevice(ctx, 42, "family-1", "ua", "ip", later); touchErr != nil {
		t.Fatalf("TouchDevice returned error: %v", touchErr)
	}
	records, err := devices.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(records) != 1 || records[0].DeviceID != "family-1" || !records[0].LastSeen.Equal(later) {
		t.Fatalf("records = %#v, want family-1 with last_seen %v", records, later)
	}

	if removeErr := devices.RemoveDevice(ctx, 42, "family-1"); removeErr != nil {
		t.Fatalf("RemoveDevice returned error: %v", removeErr)
	}
	records, err = devices.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("records = %#v, want empty after remove", records)
	}
}
