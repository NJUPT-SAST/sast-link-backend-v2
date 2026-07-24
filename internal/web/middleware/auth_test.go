package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

type testClock struct{ value time.Time }

func (c testClock) Now() time.Time { return c.value }

type fakeBlacklist struct {
	blacklisted bool
	err         error
	calls       int
}

func (f *fakeBlacklist) IsJTIBlacklisted(context.Context, string) (bool, error) {
	f.calls++
	return f.blacklisted, f.err
}

type fakeAccessStates struct {
	state *repository.AccessAuthState
	err   error
	calls int
	jti   string
}

func (f *fakeAccessStates) FindAccessAuthStateByJTI(_ context.Context, jti string) (*repository.AccessAuthState, error) {
	f.calls++
	f.jti = jti
	return f.state, f.err
}

type fakeVerifier struct {
	claims *auth.TokenClaims
	err    error
}

func (f fakeVerifier) VerifyAccessToken(string) (*auth.TokenClaims, error) {
	return f.claims, f.err
}

func TestAuthenticatorRequireAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)
	validToken := signTestToken(t, manager, auth.TokenInput{
		Subject: "42", JTI: "jti-42", Role: "member", State: "on_sast", TokenVersion: 7,
		Scopes: []string{"openid", "profile", "email"}, TTL: time.Hour,
	})
	expiredManager := newTestJWTManager(t, now)
	expiredToken := signTestToken(t, expiredManager, auth.TokenInput{
		Subject: "42", JTI: "jti-expired", Role: "member", State: "on_sast", TokenVersion: 7,
		Scopes: []string{"openid"}, TTL: time.Minute,
	})
	expiredManager.Clock = testClock{value: now.Add(2 * time.Minute)}
	badSubjectToken := signTestToken(t, manager, auth.TokenInput{
		Subject: "not-an-int", JTI: "jti-bad-sub", Role: "member", State: "on_sast", TokenVersion: 7,
		Scopes: []string{"openid"}, TTL: time.Hour,
	})

	tests := []struct {
		name      string
		header    string
		manager   *auth.JWTManager
		blacklist *fakeBlacklist
		states    *fakeAccessStates
		wantHTTP  int
		wantCode  int
	}{
		{name: "missing header", manager: manager, states: validStates(now), wantHTTP: http.StatusUnauthorized, wantCode: 40100},
		{name: "not strict bearer", header: "bearer " + validToken, manager: manager, states: validStates(now), wantHTTP: http.StatusUnauthorized, wantCode: 40100},
		{name: "expired token", header: "Bearer " + expiredToken, manager: expiredManager, states: validStates(now), wantHTTP: http.StatusUnauthorized, wantCode: 40101},
		{name: "invalid token", header: "Bearer not-a-jwt", manager: manager, states: validStates(now), wantHTTP: http.StatusUnauthorized, wantCode: 40102},
		{name: "invalid subject", header: "Bearer " + badSubjectToken, manager: manager, states: validStates(now), wantHTTP: http.StatusUnauthorized, wantCode: 40102},
		{name: "blacklisted jti", header: "Bearer " + validToken, manager: manager, blacklist: &fakeBlacklist{blacklisted: true}, states: validStates(now), wantHTTP: http.StatusUnauthorized, wantCode: 40102},
		{name: "access record absent", header: "Bearer " + validToken, manager: manager, states: &fakeAccessStates{err: repository.ErrNotFound}, wantHTTP: http.StatusUnauthorized, wantCode: 40102},
		{name: "access record revoked", header: "Bearer " + validToken, manager: manager, states: revokedStates(now), wantHTTP: http.StatusUnauthorized, wantCode: 40102},
		{name: "access record expired", header: "Bearer " + validToken, manager: manager, states: expiredStates(now), wantHTTP: http.StatusUnauthorized, wantCode: 40102},
		{name: "user deleted", header: "Bearer " + validToken, manager: manager, states: deletedStates(now), wantHTTP: http.StatusForbidden, wantCode: 40301},
		{name: "version changed", header: "Bearer " + validToken, manager: manager, states: versionChangedStates(now), wantHTTP: http.StatusUnauthorized, wantCode: 40102},
		{name: "database error", header: "Bearer " + validToken, manager: manager, states: &fakeAccessStates{err: errors.New("db unavailable")}, wantHTTP: http.StatusInternalServerError, wantCode: 50000},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder, body := performAuthRequest(test.manager, test.blacklist, test.states, now, test.header)
			if recorder.Code != test.wantHTTP || body.Code != test.wantCode {
				t.Fatalf("response = %d %#v, want %d/%d", recorder.Code, body, test.wantHTTP, test.wantCode)
			}
		})
	}
}

func TestAuthenticatorUsesSingleDBAuthStateQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)
	token := signTestToken(t, manager, auth.TokenInput{
		Subject: "42", JTI: "jti-42", Role: "member", State: "on_sast", TokenVersion: 7,
		Scopes: []string{"openid"}, TTL: time.Hour,
	})
	states := validStates(now)
	recorder, body := performAuthRequest(manager, nil, states, now, "Bearer "+token)
	if recorder.Code != http.StatusOK || body.Data["user_id"] != float64(42) || states.calls != 1 || states.jti != "jti-42" {
		t.Fatalf("response=%d %#v calls=%d jti=%q", recorder.Code, body, states.calls, states.jti)
	}
}

func TestAuthenticatorRejectsBlankJTIWithoutBlacklistLookup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	blacklist := &fakeBlacklist{}
	states := validStates(now)
	authenticator := Authenticator{
		JWT: fakeVerifier{claims: &auth.TokenClaims{RegisteredClaims: jwt.RegisteredClaims{
			Subject: "42", ID: " \t", ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		}}},
		Blacklist: blacklist,
		Tokens:    states,
		Now:       func() time.Time { return now },
	}
	router := gin.New()
	router.GET("/protected", authenticator.RequireAuth(), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer token")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || blacklist.calls != 0 || states.calls != 0 {
		t.Fatalf("status=%d blacklist calls=%d DB calls=%d", recorder.Code, blacklist.calls, states.calls)
	}
}

func performAuthRequest(manager *auth.JWTManager, blacklist *fakeBlacklist, states *fakeAccessStates, now time.Time, header string) (*httptest.ResponseRecorder, envelope) {
	router := gin.New()
	var blacklistStore JTIBlacklist
	if blacklist != nil {
		blacklistStore = blacklist
	}
	authenticator := Authenticator{JWT: manager, Blacklist: blacklistStore, Tokens: states, Now: func() time.Time { return now }}
	router.GET("/protected", authenticator.RequireAuth(), func(c *gin.Context) {
		principal, _ := PrincipalFrom(c)
		c.JSON(http.StatusOK, envelope{Code: 0, Message: "ok", Data: map[string]any{"user_id": principal.UserID, "jti": principal.JTI}})
	})
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	if header != "" {
		request.Header.Set("Authorization", header)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	var body envelope
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder, body
}

type envelope struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data"`
}

func newTestJWTManager(t *testing.T, now time.Time) *auth.JWTManager {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return &auth.JWTManager{Issuer: "https://link.sast.fun/v2", Audience: []string{"sast-link-v2"}, Active: auth.JWTKeyPair{KID: "active", Private: key}, Clock: testClock{value: now}}
}

func signTestToken(t *testing.T, manager *auth.JWTManager, input auth.TokenInput) string {
	t.Helper()
	if input.NotBefore.IsZero() {
		input.NotBefore = manager.Clock.(testClock).value
	}
	token, err := manager.SignAccessToken(input)
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	return token
}

func validStates(now time.Time) *fakeAccessStates {
	return &fakeAccessStates{state: &repository.AccessAuthState{TokenID: "jti-42", UserID: 42, UserState: model.UserStateOnSAST, TokenVersion: 7, ExpiresAt: now.Add(time.Hour)}}
}

func deletedStates(now time.Time) *fakeAccessStates {
	state := validStates(now)
	state.state.UserState = model.UserStateDeleted
	return state
}

func versionChangedStates(now time.Time) *fakeAccessStates {
	state := validStates(now)
	state.state.TokenVersion = 8
	return state
}

func revokedStates(now time.Time) *fakeAccessStates {
	state := validStates(now)
	revokedAt := now.Add(-time.Minute)
	state.state.RevokedAt = &revokedAt
	return state
}

func expiredStates(now time.Time) *fakeAccessStates {
	state := validStates(now)
	state.state.ExpiresAt = now.Add(-time.Minute)
	return state
}

func TestStrictBearerRejectsWhitespaceInToken(t *testing.T) {
	if _, ok := strictBearerToken("Bearer token extra"); ok {
		t.Fatal("strictBearerToken accepted extra whitespace")
	}
	if token, ok := strictBearerToken("Bearer token"); !ok || token != "token" {
		t.Fatalf("strictBearerToken valid = %q, %v", token, ok)
	}
}

func TestPrincipalFromMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if principal, ok := PrincipalFrom(c); ok || principal.UserID != 0 {
		t.Fatalf("PrincipalFrom missing = %+v, %v", principal, ok)
	}
}
