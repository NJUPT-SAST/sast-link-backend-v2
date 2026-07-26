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

func TestBlacklistStoreRoundTrip(t *testing.T) {
	blacklist := BlacklistStore{Store: newTestStore(t)}
	ctx := context.Background()

	if err := blacklist.BlacklistJTI(ctx, "jti-42", time.Hour); err != nil {
		t.Fatalf("blacklist JTI: %v", err)
	}
	listed, err := blacklist.IsJTIBlacklisted(ctx, "jti-42")
	if err != nil || !listed {
		t.Fatalf("IsJTIBlacklisted=%v err=%v, want blacklisted", listed, err)
	}
	listed, err = blacklist.IsJTIBlacklisted(ctx, "jti-unknown")
	if err != nil || listed {
		t.Fatalf("unknown JTI blacklisted=%v err=%v, want not blacklisted", listed, err)
	}
}
