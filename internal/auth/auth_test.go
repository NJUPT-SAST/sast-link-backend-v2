package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type fixedReader struct{ data []byte }

func (r fixedReader) Read(target []byte) (int, error) {
	for index := range target {
		target[index] = r.data[index%len(r.data)]
	}
	return len(target), nil
}

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }

func TestPasswordHasherVersionedArgon2id(t *testing.T) {
	hasher := PasswordHasher{Random: fixedReader{data: bytes.Repeat([]byte{0x42}, 16)}}
	hash, err := hasher.HashPassword(context.Background(), "fixture")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if !strings.HasPrefix(hash, "argon2id-v1$") {
		t.Fatalf("hash = %q, want versioned argon2id format", hash)
	}
	if err := hasher.VerifyPassword(context.Background(), "fixture", hash); err != nil {
		t.Fatalf("VerifyPassword returned error: %v", err)
	}
	if err := hasher.VerifyPassword(context.Background(), "wrong", hash); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("VerifyPassword wrong password error = %v, want ErrInvalidSecret", err)
	}
}

// The semaphore must bound in-flight derivations and hand the slot back when
// the call returns, or a hashing burst would queue forever after the first
// batch.
func TestPasswordHasherSemaphoreBoundsAndReleases(t *testing.T) {
	semaphore := make(chan struct{}, 1)
	hasher := PasswordHasher{Random: fixedReader{data: bytes.Repeat([]byte{0x42}, 16)}, Semaphore: semaphore}

	semaphore <- struct{}{} // occupy the only slot

	done := make(chan error, 1)
	go func() {
		_, err := hasher.HashPassword(context.Background(), "queued")
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("HashPassword completed while semaphore full: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	<-semaphore // release the slot
	if err := <-done; err != nil {
		t.Fatalf("HashPassword after release returned error: %v", err)
	}
	if len(semaphore) != 0 {
		t.Fatalf("semaphore len = %d, want 0 after released hash", len(semaphore))
	}
}

func TestRefreshTokenOpaqueAndHMAC(t *testing.T) {
	manager := RefreshTokenManager{
		Random: fixedReader{data: []byte{0x24}},
		Secret: []byte("0123456789abcdef0123456789abcdef"),
	}
	configured, err := NewRefreshTokenManager("0123456789abcdef0123456789abcdef", fixedReader{data: []byte{0x24}})
	if err != nil || configured == nil {
		t.Fatalf("NewRefreshTokenManager = %#v, %v, want configured manager", configured, err)
	}
	token, err := manager.NewRefreshToken()
	if err != nil {
		t.Fatalf("NewRefreshToken returned error: %v", err)
	}
	if !strings.HasPrefix(token, "rt_") || len(token) < 40 {
		t.Fatalf("token = %q, want rt_ high entropy token", token)
	}
	hash, err := manager.HashRefreshToken(token)
	if err != nil {
		t.Fatalf("HashRefreshToken returned error: %v", err)
	}
	if strings.Contains(hash, token) {
		t.Fatalf("hash contains token material")
	}
	if err := manager.VerifyRefreshTokenHash(token, hash); err != nil {
		t.Fatalf("VerifyRefreshTokenHash returned error: %v", err)
	}
	if err := manager.VerifyRefreshTokenHash(token+"x", hash); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("VerifyRefreshTokenHash mismatch error = %v, want ErrInvalidSecret", err)
	}
	if _, err := (RefreshTokenManager{Secret: []byte("short")}).NewRefreshToken(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NewRefreshToken weak secret error = %v, want ErrInvalidInput", err)
	}
	if _, err := NewRefreshTokenManager("short", nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NewRefreshTokenManager weak secret error = %v, want ErrInvalidInput", err)
	}
}

func TestPKCES256Only(t *testing.T) {
	verifier := strings.Repeat("a", 43)
	challenge, err := PKCEChallengeS256(verifier)
	if err != nil {
		t.Fatalf("PKCEChallengeS256 returned error: %v", err)
	}
	if err := VerifyPKCES256(verifier, challenge, "S256"); err != nil {
		t.Fatalf("VerifyPKCES256 returned error: %v", err)
	}
	if err := VerifyPKCES256(verifier, challenge, "plain"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("VerifyPKCES256 plain error = %v, want ErrInvalidInput", err)
	}
	if err := ValidatePKCEVerifier(strings.Repeat("a", 42)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("short verifier error = %v, want ErrInvalidInput", err)
	}
	if err := ValidatePKCEVerifier(strings.Repeat("a", 42) + "+"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad verifier error = %v, want ErrInvalidInput", err)
	}
}

func TestJWTManagerParsesConfiguredKeys(t *testing.T) {
	_, activeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate active key: %v", err)
	}
	_, previousKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate previous key: %v", err)
	}
	activeDER, err := x509.MarshalPKCS8PrivateKey(activeKey)
	if err != nil {
		t.Fatalf("marshal active key: %v", err)
	}
	previousDER, err := x509.MarshalPKIXPublicKey(previousKey.Public())
	if err != nil {
		t.Fatalf("marshal previous key: %v", err)
	}
	activePEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: activeDER}))
	previousPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: previousDER}))

	manager, err := NewJWTManager(JWTConfig{
		Issuer:         "https://link.sast.fun/v2",
		Audience:       "sast-link",
		ActiveKID:      "active",
		ActiveKeyPEM:   strings.ReplaceAll(activePEM, "\n", `\n`),
		PreviousKID:    "previous",
		PreviousKeyPEM: previousPEM,
	})
	if err != nil {
		t.Fatalf("NewJWTManager returned error: %v", err)
	}
	if manager.Active.Private == nil || len(manager.Previous) != 1 || len(manager.Previous[0].Public) == 0 {
		t.Fatalf("manager key configuration = %#v, want active private and previous public keys", manager)
	}
	if _, err := NewJWTManager(JWTConfig{Issuer: "issuer", Audience: "audience", ActiveKID: "kid", ActiveKeyPEM: "change_me"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NewJWTManager malformed PEM error = %v, want ErrInvalidInput", err)
	}
	if _, err := NewJWTManager(JWTConfig{
		Issuer:         "issuer",
		Audience:       "audience",
		ActiveKID:      "active",
		ActiveKeyPEM:   activePEM,
		PreviousKID:    "   ",
		PreviousKeyPEM: previousPEM,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NewJWTManager whitespace previous kid error = %v, want ErrInvalidInput", err)
	}
	if _, err := NewJWTManager(JWTConfig{
		Issuer:         "issuer",
		Audience:       "audience",
		ActiveKID:      "duplicate",
		ActiveKeyPEM:   activePEM,
		PreviousKID:    "duplicate",
		PreviousKeyPEM: previousPEM,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NewJWTManager duplicate kid error = %v, want ErrInvalidInput", err)
	}
}

func TestJWTManagerEdDSAActivePreviousAndJWKS(t *testing.T) {
	_, activeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate active key: %v", err)
	}
	_, previousKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate previous key: %v", err)
	}
	clock := fixedClock{value: time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)}
	manager := JWTManager{
		Issuer:   "https://link.sast.fun/v2",
		Audience: []string{"sast-link"},
		Active:   JWTKeyPair{KID: "active", Private: activeKey},
		Previous: []JWTKeyPair{{KID: "previous", Public: previousKey.Public().(ed25519.PublicKey)}},
		Clock:    clock,
	}
	token, err := manager.SignAccessToken(TokenInput{
		Subject:      "user-1",
		JTI:          "jti-1",
		Role:         "member",
		State:        "on_sast",
		TokenVersion: 7,
		Scopes:       []string{"email", "openid", "profile"},
		TTL:          time.Hour,
	})
	if err != nil {
		t.Fatalf("SignAccessToken returned error: %v", err)
	}
	claims, err := manager.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken returned error: %v", err)
	}
	if claims.Subject != "user-1" || claims.ID != "jti-1" || claims.Role != "member" || claims.State != "on_sast" || claims.TokenVersion != 7 || claims.Scope != "openid profile email" {
		t.Fatalf("claims = %+v, want signed SAST Link claims", claims)
	}
	assertJWTUsesScopeClaim(t, token, "openid profile email")
	previousManager := manager
	previousManager.Active = JWTKeyPair{KID: "previous", Private: previousKey}
	previousManager.Previous = nil
	previousToken, err := previousManager.SignAccessToken(TokenInput{
		Subject:      "user-2",
		JTI:          "jti-2",
		Role:         "member",
		State:        "on_sast",
		TokenVersion: 1,
		Scopes:       []string{"openid"},
		TTL:          time.Hour,
	})
	if err != nil {
		t.Fatalf("sign previous token: %v", err)
	}
	if _, err := manager.VerifyAccessToken(previousToken); err != nil {
		t.Fatalf("VerifyAccessToken previous key returned error: %v", err)
	}

	expiredManager := manager
	expiredManager.Clock = fixedClock{value: clock.value.Add(2 * time.Hour)}
	if _, err := expiredManager.VerifyAccessToken(token); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("VerifyAccessToken expired error = %v, want ErrExpiredToken", err)
	}

	jwks := manager.JWKS()
	keys, ok := jwks["keys"].([]map[string]string)
	if !ok || len(keys) != 2 {
		t.Fatalf("JWKS keys = %#v, want two public keys", jwks["keys"])
	}
	for _, key := range keys {
		if _, hasPrivate := key["d"]; hasPrivate {
			t.Fatalf("JWKS leaked private key material: %#v", key)
		}
		if key["kty"] != "OKP" || key["crv"] != "Ed25519" || key["alg"] != "EdDSA" || key["x"] == "" {
			t.Fatalf("bad JWK: %#v", key)
		}
	}
}

func TestJWTManagerRejectsIncompleteAccessTokenClaims(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	clock := fixedClock{value: time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)}
	manager := JWTManager{
		Issuer:   "https://link.sast.fun/v2",
		Audience: []string{"sast-link"},
		Active:   JWTKeyPair{KID: "active", Private: key},
		Clock:    clock,
	}
	base := TokenInput{
		Subject:      "user-1",
		JTI:          "jti-1",
		Role:         "member",
		State:        "on_sast",
		TokenVersion: 0,
		Scopes:       []string{"openid"},
		TTL:          time.Hour,
	}
	tests := []struct {
		name   string
		mutate func(*TokenInput)
	}{
		{name: "missing role", mutate: func(input *TokenInput) { input.Role = "" }},
		{name: "missing state", mutate: func(input *TokenInput) { input.State = "" }},
		{name: "missing scope", mutate: func(input *TokenInput) { input.Scopes = nil }},
		{name: "empty scope", mutate: func(input *TokenInput) { input.Scopes = []string{"openid", ""} }},
		{name: "duplicate scope", mutate: func(input *TokenInput) { input.Scopes = []string{"openid", "openid"} }},
		{name: "unknown scope", mutate: func(input *TokenInput) { input.Scopes = []string{"openid", "unknown"} }},
		{name: "missing openid", mutate: func(input *TokenInput) { input.Scopes = []string{"profile"} }},
		{name: "negative token version", mutate: func(input *TokenInput) { input.TokenVersion = -1 }},
		{name: "blank jti", mutate: func(input *TokenInput) { input.JTI = " \t" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			test.mutate(&input)
			if _, err := manager.SignAccessToken(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("SignAccessToken() error = %v, want ErrInvalidInput", err)
			}
		})
	}

	claims := jwtPayload{
		"iss":           "https://link.sast.fun/v2",
		"aud":           "sast-link",
		"sub":           "user-1",
		"jti":           "jti-1",
		"role":          "member",
		"state":         "on_sast",
		"scope":         "openid",
		"exp":           clock.value.Add(time.Hour).Unix(),
		"iat":           clock.value.Unix(),
		"nbf":           clock.value.Unix(),
		"token_version": 0,
	}
	missingTokenVersion := cloneJWTPayload(claims)
	delete(missingTokenVersion, "token_version")
	if _, err := manager.VerifyAccessToken(signRawJWT(t, manager, missingTokenVersion)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyAccessToken(missing token_version) error = %v, want ErrInvalidToken", err)
	}
	missingScope := cloneJWTPayload(claims)
	delete(missingScope, "scope")
	if _, err := manager.VerifyAccessToken(signRawJWT(t, manager, missingScope)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyAccessToken(missing scope) error = %v, want ErrInvalidToken", err)
	}
	blankJTI := cloneJWTPayload(claims)
	blankJTI["jti"] = " \t"
	if _, err := manager.VerifyAccessToken(signRawJWT(t, manager, blankJTI)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyAccessToken(blank jti) error = %v, want ErrInvalidToken", err)
	}
	for _, invalidScope := range []string{"openid unknown", "profile", "openid  profile"} {
		invalidClaims := cloneJWTPayload(claims)
		invalidClaims["scope"] = invalidScope
		if _, err := manager.VerifyAccessToken(signRawJWT(t, manager, invalidClaims)); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("VerifyAccessToken(scope=%q) error = %v, want ErrInvalidToken", invalidScope, err)
		}
	}
}

func assertJWTUsesScopeClaim(t *testing.T, token string, wantScope string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT parts = %d, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal JWT payload: %v", err)
	}
	if claims["scope"] != wantScope {
		t.Fatalf("scope claim = %#v, want %q", claims["scope"], wantScope)
	}
	if _, exists := claims["scopes"]; exists {
		t.Fatalf("unexpected legacy scopes claim: %s", payload)
	}
}

type jwtPayload map[string]any

func cloneJWTPayload(payload jwtPayload) jwtPayload {
	clone := make(jwtPayload, len(payload))
	for key, value := range payload {
		clone[key] = value
	}
	return clone
}

func signRawJWT(t *testing.T, manager JWTManager, payload jwtPayload) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims(payload))
	token.Header["kid"] = manager.Active.KID
	signed, err := token.SignedString(manager.Active.Private)
	if err != nil {
		t.Fatalf("sign raw JWT: %v", err)
	}
	return signed
}

// Bounding derivation concurrency turns CPU pressure into a queue. A single
// derivation costs roughly 380ms, and nothing else bounds the backlog (no HTTP
// WriteTimeout, per-IP-only login limits), so a caller that has gone away must
// stop occupying a queue slot instead of waiting for its turn to burn a core.
func TestPasswordHasherAbandonsQueueWhenCallerCancelled(t *testing.T) {
	semaphore := make(chan struct{}, 1)
	hasher := PasswordHasher{Random: fixedReader{data: bytes.Repeat([]byte{0x42}, 16)}, Semaphore: semaphore}
	semaphore <- struct{}{} // occupy the only slot

	ctx, cancel := context.WithCancel(context.Background())
	hashed := make(chan error, 1)
	go func() {
		_, err := hasher.HashPassword(ctx, "queued")
		hashed <- err
	}()

	select {
	case err := <-hashed:
		t.Fatalf("HashPassword returned %v while the semaphore was full", err)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-hashed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("HashPassword error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HashPassword ignored cancellation and stayed queued")
	}

	// Abandoning the wait must not leak the slot it never acquired.
	if len(semaphore) != 1 {
		t.Fatalf("semaphore len = %d, want the original holder's slot still taken", len(semaphore))
	}
	<-semaphore
}

// VerifyPassword shares the same gate, and its cancellation must be reported as
// such rather than as a password mismatch.
func TestPasswordHasherVerifyAbandonsQueueWhenCallerCancelled(t *testing.T) {
	hasher := PasswordHasher{Random: fixedReader{data: bytes.Repeat([]byte{0x42}, 16)}}
	hash, err := hasher.HashPassword(context.Background(), "fixture")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	semaphore := make(chan struct{}, 1)
	gated := PasswordHasher{Random: hasher.Random, Semaphore: semaphore}
	semaphore <- struct{}{}

	ctx, cancel := context.WithCancel(context.Background())
	verified := make(chan error, 1)
	go func() {
		verified <- gated.VerifyPassword(ctx, "fixture", hash)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-verified:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("VerifyPassword error = %v, want context.Canceled", err)
		}
		// The error must stay distinguishable from a real mismatch, or callers
		// would count an abandoned request as a failed login attempt.
		if errors.Is(err, ErrInvalidSecret) {
			t.Fatal("cancellation is indistinguishable from a wrong password")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("VerifyPassword ignored cancellation and stayed queued")
	}
	<-semaphore
}

// A context that is already done must lose even when a slot happens to be free:
// a select with both cases ready picks pseudo-randomly, which would admit
// abandoned work roughly half the time.
func TestPasswordHasherRejectsAlreadyCancelledContext(t *testing.T) {
	hasher := PasswordHasher{
		Random:    fixedReader{data: bytes.Repeat([]byte{0x42}, 16)},
		Semaphore: make(chan struct{}, 4), // deliberately idle
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for attempt := range 20 {
		if _, err := hasher.HashPassword(ctx, "abandoned"); !errors.Is(err, context.Canceled) {
			t.Fatalf("attempt %d: error = %v, want context.Canceled", attempt, err)
		}
	}
}

// An unset semaphore must keep working without a context requirement changing
// behaviour, so deployments that leave it nil are unaffected.
func TestPasswordHasherWithoutSemaphoreIgnoresCancellation(t *testing.T) {
	hasher := PasswordHasher{Random: fixedReader{data: bytes.Repeat([]byte{0x42}, 16)}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := hasher.HashPassword(ctx, "unbounded"); err != nil {
		t.Fatalf("HashPassword() with nil semaphore error = %v, want nil", err)
	}
}

// The authorize leg refuses a challenge that is 43 bytes but not base64url: a
// challenge no verifier could ever produce yields a code guaranteed to fail at
// redemption, so it is better refused while the client can still fix it.
func TestIsValidPKCEChallenge(t *testing.T) {
	valid := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" // 43 base64url chars
	for _, test := range []struct {
		name      string
		challenge string
		want      bool
	}{
		{"valid digest", valid, true},
		{"uppercase and underscore are base64url", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop_", true},
		{"too short", valid[:42], false},
		{"too long", valid + "a", false},
		{"empty", "", false},
		{"slash is not base64url", valid[:42] + "/", false},
		{"plus is not base64url", valid[:42] + "+", false},
		{"padding is not base64url", valid[:42] + "=", false},
		{"space", valid[:42] + " ", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := IsValidPKCEChallenge(test.challenge); got != test.want {
				t.Fatalf("IsValidPKCEChallenge(%q) = %v, want %v", test.challenge, got, test.want)
			}
		})
	}
}
