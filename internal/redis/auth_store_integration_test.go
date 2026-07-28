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
	if got, want := keys.OneTime("oauth:state", "abc"), "sast-link:test:oauth%3Astate:abc"; got != want {
		t.Fatalf("OneTime key = %q, want %q", got, want)
	}
	if got, want := keys.VerifyCode("register", "a@example.com"), "sast-link:test:verify:register:a@example.com"; got != want {
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
	if got, want := keys.LoginFailure("user:42"), "sast-link:test:auth:login_failure:user%3A42"; got != want {
		t.Fatalf("LoginFailure key = %q, want %q", got, want)
	}
	if got, want := keys.RateLimit("login", "ip-1"), "sast-link:test:ratelimit:ip-1:login"; got != want {
		t.Fatalf("RateLimit key = %q, want %q", got, want)
	}
	if plain, wrapped := keys.OAuthState("state"), keys.OAuthState(":state:"); plain == wrapped {
		t.Fatalf("OAuthState keys collided for dynamic state values: %q", plain)
	}
	if got, want := keys.RateLimit("login", "::1"), "sast-link:test:ratelimit:%3A%3A1:login"; got != want {
		t.Fatalf("RateLimit IPv6 key = %q, want %q", got, want)
	}
	if left, right := keys.RateLimit("login", "::1"), keys.RateLimit(":1:login", ":"); left == right {
		t.Fatalf("RateLimit keys collided for distinct tuples: %q", left)
	}
	if empty, nonEmpty := keys.OneTime("oauth:state", ""), keys.OneTime("oauth", "state"); empty == nonEmpty {
		t.Fatalf("OneTime keys collided for empty and non-empty tuples: %q", empty)
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

func TestJTIBlacklist(t *testing.T) {
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
}

// BlacklistJTIBatch backs whole-user revocation (password change/reset): every
// live JTI must land in one round trip with its own TTL.
func TestJTIBlacklistBatch(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}

	if err := store.BlacklistJTIBatch(ctx, nil); err != nil {
		t.Fatalf("BlacklistJTIBatch(nil) returned error: %v", err)
	}
	if err := store.BlacklistJTIBatch(ctx, map[string]time.Duration{
		"jti-a": 2 * time.Second,
		"jti-b": 3 * time.Second,
	}); err != nil {
		t.Fatalf("BlacklistJTIBatch returned error: %v", err)
	}
	for _, jti := range []string{"jti-a", "jti-b"} {
		blacklisted, err := store.IsJTIBlacklisted(ctx, jti)
		if err != nil || !blacklisted {
			t.Fatalf("IsJTIBlacklisted(%q) = %v, %v; want true, nil", jti, blacklisted, err)
		}
		ttl, err := client.PTTL(ctx, store.Keys.JTIBlacklist(jti)).Result()
		if err != nil || ttl <= 0 {
			t.Fatalf("PTTL(%q) = %v, %v; want positive expiry", jti, ttl, err)
		}
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

func TestLoginFailures(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}

	state, err := store.GetLoginFailures(ctx, "user:42")
	if err != nil || state.Count != 0 || state.TTL != 0 {
		t.Fatalf("initial GetLoginFailures = %+v, %v", state, err)
	}
	first, err := store.RecordLoginFailure(ctx, "user:42", 1500*time.Millisecond)
	if err != nil || first.Count != 1 || first.TTL <= time.Second {
		t.Fatalf("first RecordLoginFailure = %+v, %v", first, err)
	}
	second, err := store.RecordLoginFailure(ctx, "user:42", 1500*time.Millisecond)
	if err != nil || second.Count != 2 || second.TTL <= 0 || second.TTL > first.TTL {
		t.Fatalf("second RecordLoginFailure = %+v, %v", second, err)
	}
	if resetErr := store.ResetLoginFailures(ctx, "user:42"); resetErr != nil {
		t.Fatalf("ResetLoginFailures() error = %v", resetErr)
	}
	state, err = store.GetLoginFailures(ctx, "user:42")
	if err != nil || state.Count != 0 || state.TTL != 0 {
		t.Fatalf("GetLoginFailures after reset = %+v, %v", state, err)
	}
}

// A wrong guess used to delete the stored code outright, so anyone who knew an
// address could invalidate its verification code at will. The code must now
// survive a mismatch until the attempt budget runs out.
func TestVerifyVerificationCodeSurvivesWrongGuess(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	const (
		purpose = "register"
		email   = "survive@njupt.edu.cn"
	)
	if err := store.SaveVerificationCode(ctx, purpose, email, "123456", time.Minute); err != nil {
		t.Fatalf("SaveVerificationCode() error = %v", err)
	}

	matched, remaining, err := store.VerifyVerificationCode(ctx, purpose, email, "000000")
	if err != nil {
		t.Fatalf("VerifyVerificationCode(wrong) error = %v", err)
	}
	if matched || remaining != maximumVerificationCodeAttempts-1 {
		t.Fatalf("wrong guess = (%t, %d), want (false, %d)", matched, remaining, maximumVerificationCodeAttempts-1)
	}

	matched, _, err = store.VerifyVerificationCode(ctx, purpose, email, "123456")
	if err != nil {
		t.Fatalf("VerifyVerificationCode(correct) error = %v", err)
	}
	if !matched {
		t.Fatal("correct code rejected after one wrong guess: the guess burned it")
	}

	// A matching code is consumed, so it cannot be replayed.
	matched, remaining, err = store.VerifyVerificationCode(ctx, purpose, email, "123456")
	if err != nil {
		t.Fatalf("VerifyVerificationCode(replay) error = %v", err)
	}
	if matched || remaining != 0 {
		t.Fatalf("replay = (%t, %d), want (false, 0)", matched, remaining)
	}
}

// The attempt budget is what keeps a 6-digit code from being brute-forced, so it
// must actually terminate and must not be resettable by re-guessing.
func TestVerifyVerificationCodeExhaustsAttempts(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	const (
		purpose = "reset_password"
		email   = "brute@njupt.edu.cn"
	)
	if err := store.SaveVerificationCode(ctx, purpose, email, "123456", time.Minute); err != nil {
		t.Fatalf("SaveVerificationCode() error = %v", err)
	}

	for attempt := 1; attempt < maximumVerificationCodeAttempts; attempt++ {
		matched, remaining, err := store.VerifyVerificationCode(ctx, purpose, email, "000000")
		if err != nil {
			t.Fatalf("attempt %d error = %v", attempt, err)
		}
		if matched {
			t.Fatalf("attempt %d matched a wrong code", attempt)
		}
		if want := maximumVerificationCodeAttempts - attempt; remaining != want {
			t.Fatalf("attempt %d remaining = %d, want %d", attempt, remaining, want)
		}
	}

	matched, remaining, err := store.VerifyVerificationCode(ctx, purpose, email, "000000")
	if err != nil {
		t.Fatalf("final attempt error = %v", err)
	}
	if matched || remaining != 0 {
		t.Fatalf("final attempt = (%t, %d), want (false, 0)", matched, remaining)
	}
	// Budget spent: the code is gone, so even the correct value fails.
	if matched, _, err = store.VerifyVerificationCode(ctx, purpose, email, "123456"); err != nil {
		t.Fatalf("post-exhaustion error = %v", err)
	} else if matched {
		t.Fatal("correct code still accepted after the attempt budget was spent")
	}

	// A freshly issued code must start with a full budget rather than inherit the
	// spent one, or it would die on its first use.
	if reissueErr := store.SaveVerificationCode(ctx, purpose, email, "654321", time.Minute); reissueErr != nil {
		t.Fatalf("SaveVerificationCode(reissue) error = %v", reissueErr)
	}
	matched, remaining, err = store.VerifyVerificationCode(ctx, purpose, email, "000000")
	if err != nil {
		t.Fatalf("reissued wrong guess error = %v", err)
	}
	if matched || remaining != maximumVerificationCodeAttempts-1 {
		t.Fatalf("reissued code = (%t, %d), want (false, %d)", matched, remaining, maximumVerificationCodeAttempts-1)
	}
}

// The attempt counter must not outlive the code it guards.
func TestVerifyVerificationCodeAttemptCounterExpiresWithCode(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	const (
		purpose = "bind_email"
		email   = "ttl@njupt.edu.cn"
	)
	if err := store.SaveVerificationCode(ctx, purpose, email, "123456", 2*time.Second); err != nil {
		t.Fatalf("SaveVerificationCode() error = %v", err)
	}
	if _, _, err := store.VerifyVerificationCode(ctx, purpose, email, "000000"); err != nil {
		t.Fatalf("VerifyVerificationCode() error = %v", err)
	}
	ttl, err := client.PTTL(ctx, store.Keys.VerificationCodeAttempt(purpose, email)).Result()
	if err != nil {
		t.Fatalf("PTTL() error = %v", err)
	}
	if ttl <= 0 || ttl > 2*time.Second {
		t.Fatalf("attempt counter TTL = %v, want a positive value bounded by the code TTL", ttl)
	}
}

func TestDiscardVerificationCodeRemovesCodeAndAttempts(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	const (
		purpose = "register"
		email   = "discard@njupt.edu.cn"
	)
	if err := store.SaveVerificationCode(ctx, purpose, email, "123456", time.Minute); err != nil {
		t.Fatalf("SaveVerificationCode() error = %v", err)
	}
	if _, _, err := store.VerifyVerificationCode(ctx, purpose, email, "000000"); err != nil {
		t.Fatalf("VerifyVerificationCode() error = %v", err)
	}
	if err := store.DiscardVerificationCode(ctx, purpose, email); err != nil {
		t.Fatalf("DiscardVerificationCode() error = %v", err)
	}
	for _, key := range []string{
		store.Keys.VerifyCode(purpose, email),
		store.Keys.VerificationCodeAttempt(purpose, email),
	} {
		count, err := client.Exists(ctx, key).Result()
		if err != nil {
			t.Fatalf("Exists(%q) error = %v", key, err)
		}
		if count != 0 {
			t.Fatalf("key %q still present after discard", key)
		}
	}
}

// Peek must leave the ticket usable, and only one concurrent consumer may win it.
func TestPeekAndConsumeTicketsElectSingleWinner(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	if err := store.SaveRegisterTicket(ctx, "reg_peek", "peek@njupt.edu.cn", time.Minute); err != nil {
		t.Fatalf("SaveRegisterTicket() error = %v", err)
	}

	for range 3 {
		email, found, err := store.PeekRegisterTicket(ctx, "reg_peek")
		if err != nil || !found || email != "peek@njupt.edu.cn" {
			t.Fatalf("PeekRegisterTicket() = (%q, %t, %v), want the email preserved", email, found, err)
		}
	}

	const racers = 8
	var waitGroup sync.WaitGroup
	var winners atomic.Int64
	for range racers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			consumed, err := store.DeleteOneTime(ctx, store.Keys.RegisterTicket("reg_peek"))
			if err != nil {
				t.Errorf("DeleteOneTime() error = %v", err)
				return
			}
			if consumed {
				winners.Add(1)
			}
		}()
	}
	waitGroup.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("winners = %d, want exactly 1", got)
	}
	if _, found, err := store.PeekRegisterTicket(ctx, "reg_peek"); err != nil || found {
		t.Fatalf("PeekRegisterTicket() after consume = (%t, %v), want not found", found, err)
	}
}
