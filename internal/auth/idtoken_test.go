package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newIDTokenManager(t *testing.T, clock Clock) JWTManager {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return JWTManager{
		Issuer:   "https://link.sast.fun/v2",
		Audience: []string{"sast-link-v2"},
		Active:   JWTKeyPair{KID: "active", Private: key},
		Clock:    clock,
	}
}

func parseIDToken(t *testing.T, manager JWTManager, token string) *IDTokenClaims {
	t.Helper()
	claims := &IDTokenClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, manager.keyfunc,
		jwt.WithValidMethods([]string{jwtAlgRS256}),
		jwt.WithTimeFunc(func() time.Time { return now(manager.Clock) }),
	)
	if err != nil {
		t.Fatalf("parse ID token: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("parsed ID token is not valid")
	}
	return claims
}

func fullSubjectClaims() IDTokenSubjectClaims {
	return IDTokenSubjectClaims{
		Name:              "张三",
		Picture:           "https://cos.example.test/avatar/1.jpg",
		PreferredUsername: "zhangsan",
		Profile:           "https://link.sast.fun/card/1",
		UpdatedAt:         time.Date(2026, 7, 1, 8, 30, 0, 0, time.UTC),
		Email:             "b24040101@njupt.edu.cn",
	}
}

// The audience is the whole reason ID tokens have their own signer: it must be
// the client_id, and the resulting token must not be accepted by the access-token
// verifier, or an ID token handed to a relying party would double as a bearer
// credential for this API.
func TestSignIDTokenAudienceIsClientAndNotAnAccessToken(t *testing.T) {
	clock := fixedClock{value: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	manager := newIDTokenManager(t, clock)

	token, err := manager.SignIDToken(IDTokenInput{
		Subject:  "1",
		ClientID: "third-party-app",
		Scopes:   []string{"openid"},
		AuthTime: clock.value,
		TTL:      time.Hour,
	})
	if err != nil {
		t.Fatalf("SignIDToken returned error: %v", err)
	}

	claims := parseIDToken(t, manager, token)
	if len(claims.Audience) != 1 || claims.Audience[0] != "third-party-app" {
		t.Fatalf("aud = %v, want [third-party-app]", claims.Audience)
	}
	if claims.Issuer != "https://link.sast.fun/v2" || claims.Subject != "1" {
		t.Fatalf("iss/sub = %q/%q, want the service issuer and user ID", claims.Issuer, claims.Subject)
	}
	if claims.AuthTime != clock.value.Unix() {
		t.Fatalf("auth_time = %d, want %d", claims.AuthTime, clock.value.Unix())
	}
	if _, err := manager.VerifyAccessToken(token); err == nil {
		t.Fatal("VerifyAccessToken accepted an ID token; its audience check is not holding")
	}
}

// Scope gating is the OIDC contract: a claim outside the granted scopes must be
// absent, not present and empty, because a relying party cannot tell an empty
// string from a user who has no name.
func TestSignIDTokenEmitsOnlyGrantedScopeClaims(t *testing.T) {
	clock := fixedClock{value: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	manager := newIDTokenManager(t, clock)
	subject := fullSubjectClaims()

	tests := []struct {
		name              string
		scopes            []string
		wantName          string
		wantEmail         string
		wantEmailVerified bool
		wantUpdatedAt     int64
	}{
		{name: "openid only", scopes: []string{"openid"}},
		{
			name:          "openid profile",
			scopes:        []string{"openid", "profile"},
			wantName:      "张三",
			wantUpdatedAt: subject.UpdatedAt.Unix(),
		},
		{
			name:              "openid email",
			scopes:            []string{"openid", "email"},
			wantEmail:         "b24040101@njupt.edu.cn",
			wantEmailVerified: true,
		},
		{
			name:              "all scopes",
			scopes:            []string{"openid", "profile", "email"},
			wantName:          "张三",
			wantUpdatedAt:     subject.UpdatedAt.Unix(),
			wantEmail:         "b24040101@njupt.edu.cn",
			wantEmailVerified: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := manager.SignIDToken(IDTokenInput{
				Subject:  "1",
				ClientID: "app",
				Scopes:   test.scopes,
				AuthTime: clock.value,
				TTL:      time.Hour,
				Claims:   subject,
			})
			if err != nil {
				t.Fatalf("SignIDToken returned error: %v", err)
			}
			claims := parseIDToken(t, manager, token)
			if claims.Name != test.wantName {
				t.Fatalf("name = %q, want %q", claims.Name, test.wantName)
			}
			if claims.UpdatedAt != test.wantUpdatedAt {
				t.Fatalf("updated_at = %d, want %d", claims.UpdatedAt, test.wantUpdatedAt)
			}
			if claims.Email != test.wantEmail {
				t.Fatalf("email = %q, want %q", claims.Email, test.wantEmail)
			}
			switch {
			case test.wantEmailVerified && (claims.EmailVerified == nil || !*claims.EmailVerified):
				t.Fatalf("email_verified = %v, want true", claims.EmailVerified)
			case !test.wantEmailVerified && claims.EmailVerified != nil:
				t.Fatalf("email_verified = %v, want omitted without the email scope", *claims.EmailVerified)
			}
			// preferred_username and profile ride the profile scope alongside name.
			wantPreferred := ""
			wantProfile := ""
			if test.wantName != "" {
				wantPreferred = subject.PreferredUsername
				wantProfile = subject.Profile
			}
			if claims.PreferredUsername != wantPreferred || claims.Profile != wantProfile {
				t.Fatalf("preferred_username/profile = %q/%q, want %q/%q",
					claims.PreferredUsername, claims.Profile, wantPreferred, wantProfile)
			}
		})
	}
}

func TestSignIDTokenEchoesNonce(t *testing.T) {
	clock := fixedClock{value: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	manager := newIDTokenManager(t, clock)

	token, err := manager.SignIDToken(IDTokenInput{
		Subject:  "1",
		ClientID: "app",
		Scopes:   []string{"openid"},
		Nonce:    "n-0S6_WzA2Mj",
		AuthTime: clock.value,
		TTL:      time.Hour,
	})
	if err != nil {
		t.Fatalf("SignIDToken returned error: %v", err)
	}
	if claims := parseIDToken(t, manager, token); claims.Nonce != "n-0S6_WzA2Mj" {
		t.Fatalf("nonce = %q, want the authorization request nonce", claims.Nonce)
	}

	withoutNonce, err := manager.SignIDToken(IDTokenInput{
		Subject:  "1",
		ClientID: "app",
		Scopes:   []string{"openid"},
		AuthTime: clock.value,
		TTL:      time.Hour,
	})
	if err != nil {
		t.Fatalf("SignIDToken without nonce returned error: %v", err)
	}
	if claims := parseIDToken(t, manager, withoutNonce); claims.Nonce != "" {
		t.Fatalf("nonce = %q, want omitted when the request carried none", claims.Nonce)
	}
}

func TestSignIDTokenRejectsInvalidInput(t *testing.T) {
	clock := fixedClock{value: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	manager := newIDTokenManager(t, clock)
	valid := IDTokenInput{
		Subject:  "1",
		ClientID: "app",
		Scopes:   []string{"openid"},
		AuthTime: clock.value,
		TTL:      time.Hour,
	}

	tests := []struct {
		name   string
		mutate func(*IDTokenInput)
	}{
		{name: "empty subject", mutate: func(i *IDTokenInput) { i.Subject = "" }},
		{name: "blank client", mutate: func(i *IDTokenInput) { i.ClientID = "   " }},
		{name: "no TTL", mutate: func(i *IDTokenInput) { i.TTL = 0 }},
		{name: "zero auth_time", mutate: func(i *IDTokenInput) { i.AuthTime = time.Time{} }},
		// openid is mandatory for every token this service issues, so a scope set
		// without it is not a valid ID token request.
		{name: "scopes without openid", mutate: func(i *IDTokenInput) { i.Scopes = []string{"profile"} }},
		{name: "empty scopes", mutate: func(i *IDTokenInput) { i.Scopes = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			test.mutate(&input)
			if _, err := manager.SignIDToken(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("SignIDToken error = %v, want ErrInvalidInput", err)
			}
		})
	}
}
