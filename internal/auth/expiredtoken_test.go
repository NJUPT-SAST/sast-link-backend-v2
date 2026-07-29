package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"
)

// expiredTokenManager builds a manager whose clock is well past the token it signs,
// returning the signed token and a manager that considers it expired.
func expiredTokenManager(t *testing.T) (JWTManager, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signedAt := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	manager := JWTManager{
		Issuer:   "https://link.sast.fun/v2",
		Audience: []string{"sast-link"},
		Active:   JWTKeyPair{KID: "active", Private: key},
		Clock:    fixedClock{value: signedAt},
	}
	token, err := manager.SignAccessToken(TokenInput{
		Subject:      "user-1",
		JTI:          "jti-1",
		Role:         "member",
		State:        "on_sast",
		TokenVersion: 3,
		Scopes:       []string{"openid"},
		TTL:          time.Hour,
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	expired := manager
	expired.Clock = fixedClock{value: signedAt.Add(48 * time.Hour)}
	return expired, token
}

// The whole point: a token past its exp still yields its claims, so RFC 7009
// revocation can read the jti and cut the family the token belongs to.
func TestVerifyExpiredAccessTokenAcceptsExpiredToken(t *testing.T) {
	manager, token := expiredTokenManager(t)

	if _, err := manager.VerifyAccessToken(token); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("VerifyAccessToken() error = %v, want ErrExpiredToken", err)
	}

	claims, err := manager.VerifyExpiredAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyExpiredAccessToken() error = %v, want the claims", err)
	}
	if claims.ID != "jti-1" || claims.Subject != "user-1" {
		t.Fatalf("claims = %+v, want jti-1 / user-1", claims)
	}
}

// An unexpired token is still fine here; relaxing expiry does not mean requiring it.
func TestVerifyExpiredAccessTokenAcceptsLiveToken(t *testing.T) {
	manager, token := expiredTokenManager(t)
	manager.Clock = fixedClock{value: time.Date(2026, 7, 20, 10, 30, 0, 0, time.UTC)}

	if _, err := manager.VerifyExpiredAccessToken(token); err != nil {
		t.Fatalf("VerifyExpiredAccessToken() error = %v, want success", err)
	}
}

// Expiry is the ONLY thing forgiven. These are the cases a naive implementation
// breaks: jwt.WithoutClaimsValidation would disable issuer and audience checking
// outright, and a back-shifted clock would make a fresh token read as not-yet-valid.
// A forged jti is the whole reason the signature still has to hold.
func TestVerifyExpiredAccessTokenStillEnforcesEverythingElse(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*JWTManager)
	}{
		{"foreign issuer", func(m *JWTManager) { m.Issuer = "https://other.example" }},
		{"foreign audience", func(m *JWTManager) { m.Audience = []string{"other-service"} }},
		{"unknown kid", func(m *JWTManager) { m.Active = JWTKeyPair{KID: "rotated", Private: m.Active.Private} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, token := expiredTokenManager(t)
			test.mutate(&manager)

			if _, err := manager.VerifyExpiredAccessToken(token); err == nil {
				t.Fatal("VerifyExpiredAccessToken() accepted a token it must reject")
			}
		})
	}
}

// A token signed by a key this service does not know must be refused, or the relaxed
// check would become a way to revoke an arbitrary family by forging a jti.
func TestVerifyExpiredAccessTokenRejectsForeignSignature(t *testing.T) {
	manager, _ := expiredTokenManager(t)
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}
	forger := manager
	forger.Active = JWTKeyPair{KID: "active", Private: attackerKey}
	forger.Clock = fixedClock{value: time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)}
	forged, err := forger.SignAccessToken(TokenInput{
		Subject: "user-1", JTI: "victim-jti", Role: "member", State: "on_sast",
		Scopes: []string{"openid"}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}

	if _, err := manager.VerifyExpiredAccessToken(forged); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyExpiredAccessToken() error = %v, want ErrInvalidToken", err)
	}
}

// An ID Token must not pass as an access token here either: it carries no role, state
// or jti, which validateTokenClaims still requires.
func TestVerifyExpiredAccessTokenRejectsIDToken(t *testing.T) {
	manager, _ := expiredTokenManager(t)
	signer := manager
	signer.Clock = fixedClock{value: time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)}
	idToken, err := signer.SignIDToken(IDTokenInput{
		Subject:  "user-1",
		ClientID: "some-client",
		Scopes:   []string{"openid"},
		AuthTime: time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC),
		TTL:      time.Hour,
	})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}

	if _, err := manager.VerifyExpiredAccessToken(idToken); err == nil {
		t.Fatal("VerifyExpiredAccessToken() accepted an ID Token as an access token")
	}
}
