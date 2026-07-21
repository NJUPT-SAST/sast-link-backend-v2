package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
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

func TestPasswordHasherVersionedPBKDF2(t *testing.T) {
	hasher := PasswordHasher{Random: fixedReader{data: bytes.Repeat([]byte{0x42}, 16)}}
	hash, err := hasher.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if !strings.HasPrefix(hash, "pbkdf2-sha512-v1$600000$") {
		t.Fatalf("hash = %q, want versioned PBKDF2-SHA512 format", hash)
	}
	if err := hasher.VerifyPassword("correct horse battery staple", hash); err != nil {
		t.Fatalf("VerifyPassword returned error: %v", err)
	}
	if err := hasher.VerifyPassword("wrong", hash); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("VerifyPassword wrong password error = %v, want ErrInvalidSecret", err)
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
	activeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate active key: %v", err)
	}
	previousKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate previous key: %v", err)
	}
	activeDER, err := x509.MarshalPKCS8PrivateKey(activeKey)
	if err != nil {
		t.Fatalf("marshal active key: %v", err)
	}
	previousDER, err := x509.MarshalPKIXPublicKey(&previousKey.PublicKey)
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
	if manager.Active.Private == nil || len(manager.Previous) != 1 || manager.Previous[0].Public == nil {
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

func TestJWTManagerRS256ActivePreviousAndJWKS(t *testing.T) {
	activeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate active key: %v", err)
	}
	previousKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate previous key: %v", err)
	}
	clock := fixedClock{value: time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)}
	manager := JWTManager{
		Issuer:   "https://link.sast.fun/v2",
		Audience: []string{"sast-link"},
		Active:   JWTKeyPair{KID: "active", Private: activeKey},
		Previous: []JWTKeyPair{{KID: "previous", Public: &previousKey.PublicKey}},
		Clock:    clock,
	}
	token, err := manager.SignAccessToken(TokenInput{
		Subject:      "user-1",
		JTI:          "jti-1",
		Role:         "member",
		State:        "on_sast",
		TokenVersion: 7,
		Scopes:       []string{"openid", "profile"},
		TTL:          time.Hour,
	})
	if err != nil {
		t.Fatalf("SignAccessToken returned error: %v", err)
	}
	claims, err := manager.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken returned error: %v", err)
	}
	if claims.Subject != "user-1" || claims.ID != "jti-1" || claims.Role != "member" || claims.State != "on_sast" || claims.TokenVersion != 7 || claims.Scope != "openid profile" {
		t.Fatalf("claims = %+v, want signed SAST Link claims", claims)
	}
	assertJWTUsesScopeClaim(t, token, "openid profile")
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
			t.Fatalf("JWKS leaked private exponent: %#v", key)
		}
		if key["kty"] != "RSA" || key["alg"] != "RS256" || key["n"] == "" || key["e"] == "" {
			t.Fatalf("bad JWK: %#v", key)
		}
	}
}

func TestJWTManagerRejectsIncompleteAccessTokenClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
		{name: "negative token version", mutate: func(input *TokenInput) { input.TokenVersion = -1 }},
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
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(payload))
	token.Header["kid"] = manager.Active.KID
	signed, err := token.SignedString(manager.Active.Private)
	if err != nil {
		t.Fatalf("sign raw JWT: %v", err)
	}
	return signed
}
