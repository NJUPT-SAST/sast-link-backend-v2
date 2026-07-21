package redis

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
)

type oneTimePayload struct {
	UserID string   `json:"user_id"`
	Scopes []string `json:"scopes"`
}

func TestKeys(t *testing.T) {
	keys := NewKeys("sast-link:test")
	if got, want := keys.OneTime("oauth:state", "abc"), "sast-link:test:oauth:state:abc"; got != want {
		t.Fatalf("OneTime key = %q, want %q", got, want)
	}
	if got, want := keys.VerifyCode("a@example.com"), "sast-link:test:verify:a@example.com"; got != want {
		t.Fatalf("VerifyCode key = %q, want %q", got, want)
	}
	if got, want := keys.RegisterTicket("reg_abc"), "sast-link:test:auth:register_ticket:reg_abc"; got != want {
		t.Fatalf("RegisterTicket key = %q, want %q", got, want)
	}
	if got, want := keys.BindTicket("bind_abc"), "sast-link:test:auth:bind_ticket:bind_abc"; got != want {
		t.Fatalf("BindTicket key = %q, want %q", got, want)
	}
	if got, want := keys.LoginCode("lc_abc"), "sast-link:test:auth:login_code:lc_abc"; got != want {
		t.Fatalf("LoginCode key = %q, want %q", got, want)
	}
	if got, want := keys.OAuthState("state"), "sast-link:test:oauth:state:state"; got != want {
		t.Fatalf("OAuthState key = %q, want %q", got, want)
	}
	if got, want := keys.OAuthRegistration("state"), "sast-link:test:oauth:registration:state"; got != want {
		t.Fatalf("OAuthRegistration key = %q, want %q", got, want)
	}
	if got, want := keys.JTIBlacklist("jti"), "sast-link:test:token:blacklist:jti"; got != want {
		t.Fatalf("JTIBlacklist key = %q, want %q", got, want)
	}
	if got, want := keys.TokenVersion("u1"), "sast-link:test:token:version:u1"; got != want {
		t.Fatalf("TokenVersion key = %q, want %q", got, want)
	}
	if got, want := keys.RateLimit("login", "ip-1"), "sast-link:test:ratelimit:ip-1:login"; got != want {
		t.Fatalf("RateLimit key = %q, want %q", got, want)
	}
	if plain, wrapped := keys.OAuthState("state"), keys.OAuthState(":state:"); plain == wrapped {
		t.Fatalf("OAuthState keys collided for dynamic state values: %q", plain)
	}
	if got, want := keys.RateLimit("login", "::1"), "sast-link:test:ratelimit:::1:login"; got != want {
		t.Fatalf("RateLimit IPv6 key = %q, want %q", got, want)
	}
}

func TestStoreOneTimeTTLNXAndGetDel(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	key := store.Keys.OneTime("registration_state", "state-1")
	payload := oneTimePayload{UserID: "user-1", Scopes: []string{"openid"}}

	if err := store.SetOneTime(ctx, key, payload, 3*time.Second); err != nil {
		t.Fatalf("SetOneTime returned error: %v", err)
	}
	if err := store.SetOneTime(ctx, key, payload, 3*time.Second); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("SetOneTime duplicate error = %v, want ErrAlreadyExists", err)
	}
	ttl, err := client.TTL(ctx, key).Result()
	if err != nil {
		t.Fatalf("TTL returned error: %v", err)
	}
	if ttl <= 0 || ttl > 3*time.Second {
		t.Fatalf("TTL = %v, want positive TTL <= 3s", ttl)
	}
	var got oneTimePayload
	if err := store.GetDelOneTime(ctx, key, &got); err != nil {
		t.Fatalf("GetDelOneTime returned error: %v", err)
	}
	if got.UserID != payload.UserID || len(got.Scopes) != 1 || got.Scopes[0] != "openid" {
		t.Fatalf("payload = %+v, want %+v", got, payload)
	}
	if err := store.GetDelOneTime(ctx, key, &got); !errors.Is(err, ErrMiss) {
		t.Fatalf("GetDelOneTime second error = %v, want ErrMiss", err)
	}
}

func TestStoreOneTimeConcurrentGetDel(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	key := store.Keys.OneTime("login_code", "code-1")
	if err := store.SetOneTime(ctx, key, oneTimePayload{UserID: "user-1"}, time.Minute); err != nil {
		t.Fatalf("SetOneTime returned error: %v", err)
	}

	var successes atomic.Int32
	var waitGroup sync.WaitGroup
	for range 32 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			var payload oneTimePayload
			err := store.GetDelOneTime(ctx, key, &payload)
			if err == nil && payload.UserID == "user-1" {
				successes.Add(1)
				return
			}
			if err != nil && !errors.Is(err, ErrMiss) {
				t.Errorf("GetDelOneTime returned unexpected error: %v", err)
			}
		}()
	}
	waitGroup.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful GetDel calls = %d, want 1", successes.Load())
	}
}

func TestJTIAndTokenVersion(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	blacklisted, err := store.IsJTIBlacklisted(ctx, "jti-1")
	if err != nil {
		t.Fatalf("IsJTIBlacklisted returned error: %v", err)
	}
	if blacklisted {
		t.Fatal("JTI unexpectedly blacklisted")
	}
	blacklistErr := store.BlacklistJTI(ctx, "jti-1", 2*time.Second)
	if blacklistErr != nil {
		t.Fatalf("BlacklistJTI returned error: %v", blacklistErr)
	}
	blacklisted, err = store.IsJTIBlacklisted(ctx, "jti-1")
	if err != nil || !blacklisted {
		t.Fatalf("IsJTIBlacklisted = %v, %v; want true, nil", blacklisted, err)
	}
	versionErr := store.SetTokenVersion(ctx, "user-1", 9, time.Minute)
	if versionErr != nil {
		t.Fatalf("SetTokenVersion returned error: %v", versionErr)
	}
	version, ok, err := store.GetTokenVersion(ctx, "user-1")
	if err != nil || !ok || version != 9 {
		t.Fatalf("GetTokenVersion = %d, %v, %v; want 9, true, nil", version, ok, err)
	}
}

func TestFixedWindowLimiter(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	limiter := FixedWindowLimiter{Client: client, Keys: NewKeys("sast-link:test"), Limit: 2, Window: 1500 * time.Millisecond}

	first, err := limiter.Allow(ctx, "login", "ip-1")
	if err != nil {
		t.Fatalf("Allow first returned error: %v", err)
	}
	if !first.Allowed || first.Remaining != 1 || first.Limit != 2 {
		t.Fatalf("first result = %+v, want allowed with 1 remaining", first)
	}
	ttl, err := client.PTTL(ctx, limiter.Keys.RateLimit("login", "ip-1")).Result()
	if err != nil {
		t.Fatalf("PTTL returned error: %v", err)
	}
	if ttl <= time.Second {
		t.Fatalf("limiter TTL = %v, want fractional window preserved above 1s", ttl)
	}
	second, err := limiter.Allow(ctx, "login", "ip-1")
	if err != nil {
		t.Fatalf("Allow second returned error: %v", err)
	}
	if !second.Allowed || second.Remaining != 0 {
		t.Fatalf("second result = %+v, want allowed with 0 remaining", second)
	}
	third, err := limiter.Allow(ctx, "login", "ip-1")
	if err != nil {
		t.Fatalf("Allow third returned error: %v", err)
	}
	if third.Allowed || third.Remaining != 0 || third.RetryAfter <= 0 {
		t.Fatalf("third result = %+v, want denied with retry-after", third)
	}
}
