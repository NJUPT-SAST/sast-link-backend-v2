package middleware

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

// testInternalClientID is the built-in first-party client these tests issue for.
const testInternalClientID = "sast-link-web"

type testClock struct{ value time.Time }

func (c testClock) Now() time.Time { return c.value }

type fakeAuthStateCache struct {
	data  []byte
	found bool
	err   error
	gets  int
	puts  int
}

func (f *fakeAuthStateCache) GetAuthState(context.Context, string) ([]byte, bool, error) {
	f.gets++
	return f.data, f.found, f.err
}

func (f *fakeAuthStateCache) PutAuthState(context.Context, string, []byte, time.Duration) error {
	f.puts++
	return nil
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
	// expiredErr is returned by VerifyExpiredAccessToken; when VerifyAccessToken
	// reports ErrExpiredToken and this is nil, the expired-token path succeeds
	// (the RFC 7009 pattern: everything but the clock verifies).
	expiredErr error
}

func (f fakeVerifier) VerifyAccessToken(string) (*auth.TokenClaims, error) {
	return f.claims, f.err
}

func (f fakeVerifier) VerifyExpiredAccessToken(string) (*auth.TokenClaims, error) {
	return f.claims, f.expiredErr
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
		name     string
		header   string
		manager  *auth.JWTManager
		cache    *fakeAuthStateCache
		states   *fakeAccessStates
		wantHTTP int
		wantCode int
	}{
		{name: "missing header", manager: manager, states: validStates(now), wantHTTP: http.StatusUnauthorized, wantCode: errcode.CodeUnauthenticated},
		{name: "not strict bearer", header: "bearer " + validToken, manager: manager, states: validStates(now), wantHTTP: http.StatusUnauthorized, wantCode: errcode.CodeUnauthenticated},
		{name: "expired token", header: "Bearer " + expiredToken, manager: expiredManager, states: validStates(now), wantHTTP: http.StatusUnauthorized, wantCode: errcode.CodeAccessTokenExpired},
		{name: "invalid token", header: "Bearer not-a-jwt", manager: manager, states: validStates(now), wantHTTP: http.StatusUnauthorized, wantCode: errcode.CodeAccessTokenInvalid},
		{name: "invalid subject", header: "Bearer " + badSubjectToken, manager: manager, states: validStates(now), wantHTTP: http.StatusUnauthorized, wantCode: errcode.CodeAccessTokenInvalid},
		{name: "access record absent", header: "Bearer " + validToken, manager: manager, states: &fakeAccessStates{err: repository.ErrNotFound}, wantHTTP: http.StatusUnauthorized, wantCode: errcode.CodeAccessTokenInvalid},
		{name: "access record revoked", header: "Bearer " + validToken, manager: manager, states: revokedStates(now), wantHTTP: http.StatusUnauthorized, wantCode: errcode.CodeAccessTokenInvalid},
		{name: "access record expired", header: "Bearer " + validToken, manager: manager, states: expiredStates(now), wantHTTP: http.StatusUnauthorized, wantCode: errcode.CodeAccessTokenInvalid},
		{name: "user deleted", header: "Bearer " + validToken, manager: manager, states: deletedStates(now), wantHTTP: http.StatusForbidden, wantCode: errcode.CodeAccountDeleted},
		{name: "version changed", header: "Bearer " + validToken, manager: manager, states: versionChangedStates(now), wantHTTP: http.StatusUnauthorized, wantCode: errcode.CodeAccessTokenInvalid},
		{name: "database error", header: "Bearer " + validToken, manager: manager, states: &fakeAccessStates{err: errors.New("db unavailable")}, wantHTTP: http.StatusInternalServerError, wantCode: errcode.CodeInternal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder, body := performAuthRequest(test.manager, test.cache, test.states, now, test.header)
			if recorder.Code != test.wantHTTP || body.Code != test.wantCode {
				t.Fatalf("response = %d %#v, want %d/%d", recorder.Code, body, test.wantHTTP, test.wantCode)
			}
		})
	}
}

// A cache hit must serve the request without touching the database: that is the
// whole point of the auth-state cache. A cache error must fail open to the DB.
func TestAuthenticatorServesAuthStateFromCache(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)
	token := signTestToken(t, manager, auth.TokenInput{
		Subject: "42", JTI: "jti-42", Role: "member", State: "on_sast", TokenVersion: 7,
		Scopes: []string{"openid", "profile", "email"}, TTL: time.Hour,
	})
	state := validStates(now).state
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal cached state: %v", err)
	}

	states := &fakeAccessStates{state: state}
	cache := &fakeAuthStateCache{data: data, found: true}
	recorder, body := performAuthRequest(manager, cache, states, now, "Bearer "+token)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("cache-hit response = %d %#v, want 200/0", recorder.Code, body)
	}
	if states.calls != 0 {
		t.Fatalf("database calls = %d, want 0 on a cache hit", states.calls)
	}

	// A cache error must degrade to the database, never reject the request.
	states2 := &fakeAccessStates{state: state}
	failing := &fakeAuthStateCache{err: errors.New("redis down")}
	recorder2, body2 := performAuthRequest(manager, failing, states2, now, "Bearer "+token)
	if recorder2.Code != http.StatusOK || body2.Code != 0 || states2.calls != 1 {
		t.Fatalf("cache-error response = %d %#v (db calls %d), want 200/0 with DB fallback", recorder2.Code, body2, states2.calls)
	}
}

func performAuthRequest(manager *auth.JWTManager, cache *fakeAuthStateCache, states *fakeAccessStates, now time.Time, header string) (*httptest.ResponseRecorder, envelope) {
	router := gin.New()
	var cacheStore AuthStateCache
	if cache != nil {
		cacheStore = cache
	}
	authenticator := Authenticator{JWT: manager, Tokens: states, AuthStateCache: cacheStore, AuthStateTTL: time.Minute, Clock: testClock{value: now}, InternalClientID: testInternalClientID}
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

func performLogoutAuthRequest(manager *auth.JWTManager, states *fakeAccessStates, now time.Time, header string) (*httptest.ResponseRecorder, envelope) {
	router := gin.New()
	authenticator := Authenticator{JWT: manager, Tokens: states, AuthStateCache: &fakeAuthStateCache{}, AuthStateTTL: time.Minute, Clock: testClock{value: now}, InternalClientID: testInternalClientID}
	router.POST("/logout", authenticator.RequireUserLogoutAuth(), func(c *gin.Context) {
		principal, _ := PrincipalFrom(c)
		c.JSON(http.StatusOK, envelope{Code: 0, Message: "ok", Data: map[string]any{"user_id": principal.UserID, "jti": principal.JTI}})
	})
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/logout", nil)
	if header != "" {
		request.Header.Set("Authorization", header)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	var body envelope
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder, body
}

// Logout admits an expired access token so a stale tab can end its session: the
// RFC 7009 expired-token path re-parses the claims and skips the auth-state
// cache (the service confirms the row before revoking — an idempotent success
// when the row is gone). A fresh token runs the full chain as usual; an invalid
// signature is still rejected; the scoped gate applies to the expired path too.
func TestAuthenticatorUserLogoutToleratesExpiredToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	expiredManager := newTestJWTManager(t, now)
	expiredToken := signTestToken(t, expiredManager, auth.TokenInput{
		Subject: "42", JTI: "jti-42", Role: "member", State: "on_sast", TokenVersion: 7,
		Scopes: []string{"openid"}, TTL: time.Minute,
	})
	expiredManager.Clock = testClock{value: now.Add(2 * time.Minute)}

	// Expired but signature-valid: admitted, and the auth-state cache is never
	// touched.
	states := validStates(now)
	recorder, body := performLogoutAuthRequest(expiredManager, states, now, "Bearer "+expiredToken)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("expired-token logout = %d %#v, want 200/0", recorder.Code, body)
	}
	if states.calls != 0 {
		t.Fatalf("auth-state queries = %d, want 0 on the expired path", states.calls)
	}

	// A fresh token runs the full chain: the auth-state query happens.
	manager := newTestJWTManager(t, now)
	freshToken := signTestToken(t, manager, auth.TokenInput{
		Subject: "42", JTI: "jti-42", Role: "member", State: "on_sast", TokenVersion: 7,
		Scopes: []string{"openid"}, TTL: time.Hour,
	})
	states2 := validStates(now)
	recorder2, body2 := performLogoutAuthRequest(manager, states2, now, "Bearer "+freshToken)
	if recorder2.Code != http.StatusOK || body2.Code != 0 || states2.calls != 1 {
		t.Fatalf("fresh-token logout = %d %#v (calls %d), want 200/0 with one state query", recorder2.Code, body2, states2.calls)
	}

	// An invalid signature is rejected on the expired path too — an
	// attacker-chosen jti must not revoke an arbitrary family.
	recorder3, body3 := performLogoutAuthRequest(expiredManager, states, now, "Bearer not-a-jwt")
	if recorder3.Code != http.StatusUnauthorized {
		t.Fatalf("invalid-signature logout = %d %#v, want 401", recorder3.Code, body3)
	}

	// A third-party token whose claims carry no user scope is refused even when
	// expired: the scoped gate applies to the expired path exactly as to a fresh one.
	thirdPartyManager := newTestJWTManager(t, now)
	thirdPartyExpired := signTestToken(t, thirdPartyManager, auth.TokenInput{
		Subject: "42", JTI: "jti-3p", AuthorizedParty: "third-party-client", Role: "member", State: "on_sast",
		TokenVersion: 7, Scopes: []string{"openid"}, TTL: time.Minute,
	})
	thirdPartyManager.Clock = testClock{value: now.Add(2 * time.Minute)}
	recorder4, body4 := performLogoutAuthRequest(thirdPartyManager, states, now, "Bearer "+thirdPartyExpired)
	if recorder4.Code != http.StatusForbidden {
		t.Fatalf("third-party expired logout without user scope = %d %#v, want 403", recorder4.Code, body4)
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

func TestAuthenticatorRejectsBlankJTIWithoutAuthStateLookup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	cache := &fakeAuthStateCache{}
	states := validStates(now)
	authenticator := Authenticator{
		JWT: fakeVerifier{claims: &auth.TokenClaims{RegisteredClaims: jwt.RegisteredClaims{
			Subject: "42", ID: " \t", ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		}}},
		Tokens:           states,
		AuthStateCache:   cache,
		AuthStateTTL:     time.Minute,
		Clock:            testClock{value: now},
		InternalClientID: testInternalClientID,
	}
	router := gin.New()
	router.GET("/protected", authenticator.RequireAuth(), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer token")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || cache.gets != 0 || states.calls != 0 {
		t.Fatalf("status=%d cache gets=%d DB calls=%d", recorder.Code, cache.gets, states.calls)
	}
}

type envelope struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data"`
}

func newTestJWTManager(t *testing.T, now time.Time) *auth.JWTManager {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
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

// The scheme name is matched exactly, which RFC 7235 §2.1 does not require — it
// defines the scheme as case-insensitive, so "bearer" names the same scheme.
//
// Kept strict deliberately, and asserted here so the choice is visible rather than
// incidental: every current caller is either this project's own frontend or a test.
// Revisit if a third-party OIDC library ever fails against /userinfo, where the
// header spelling is not ours to dictate and the rejection surfaces as a misleading
// invalid_token. See the "not strict bearer" case in TestAuthenticatorRequireAuth.
func TestStrictBearerSchemeIsCaseSensitive(t *testing.T) {
	for _, header := range []string{"bearer t", "BEARER t", "BeArEr t"} {
		if _, ok := strictBearerToken(header); ok {
			t.Errorf("strictBearerToken(%q) accepted a non-canonical scheme spelling", header)
		}
	}
	for _, header := range []string{"Basic t", "Bearerx t", "Bearer", "Bearer "} {
		if _, ok := strictBearerToken(header); ok {
			t.Errorf("strictBearerToken(%q) accepted a non-Bearer or empty credential", header)
		}
	}
}

func TestPrincipalFromMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if principal, ok := PrincipalFrom(c); ok || principal.UserID != 0 {
		t.Fatalf("PrincipalFrom missing = %+v, %v", principal, ok)
	}
}

// A third-party OAuth access token must not authenticate on the internal API.
// Every access token names this service as its audience, so azp is the only claim
// that distinguishes them; without this gate an openid-only third-party grant
// reaches PUT /user/profile and the email-binding endpoints, which is account
// takeover.
func TestAuthenticatorRejectsThirdPartyAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)
	token := signTestToken(t, manager, auth.TokenInput{
		Subject: "42", JTI: "jti-42", Role: "member", State: "on_sast", TokenVersion: 7,
		Scopes: []string{"openid"}, TTL: time.Hour,
		AuthorizedParty: "some-third-party-app",
	})
	recorder, body := performAuthRequest(manager, nil, validStates(now), now, "Bearer "+token)
	if recorder.Code != http.StatusForbidden || body.Code != errcode.CodeForbidden {
		t.Fatalf("response = %d %#v, want 403/%d", recorder.Code, body, errcode.CodeForbidden)
	}
}

// The built-in client's own tokens must still pass.
func TestAuthenticatorAcceptsInternalClientToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)
	token := signTestToken(t, manager, auth.TokenInput{
		Subject: "42", JTI: "jti-42", Role: "member", State: "on_sast", TokenVersion: 7,
		Scopes: []string{"openid"}, TTL: time.Hour,
		AuthorizedParty: testInternalClientID,
	})
	recorder, body := performAuthRequest(manager, nil, validStates(now), now, "Bearer "+token)
	if recorder.Code != http.StatusOK || body.Data["user_id"] != float64(42) {
		t.Fatalf("response = %d %#v, want 200 and user 42", recorder.Code, body)
	}
}

// A missing InternalClientID must reject rather than admit every client: a
// deployment that forgets it should fail loudly, not silently drop the check.
func TestAuthenticatorFailsClosedWithoutInternalClientID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)
	token := signTestToken(t, manager, auth.TokenInput{
		Subject: "42", JTI: "jti-42", Role: "member", State: "on_sast", TokenVersion: 7,
		Scopes: []string{"openid"}, TTL: time.Hour, AuthorizedParty: testInternalClientID,
	})
	router := gin.New()
	authenticator := Authenticator{JWT: manager, Tokens: validStates(now), Clock: testClock{value: now}}
	router.GET("/protected", authenticator.RequireAuth(), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("response = %d, want 500 (fail closed)", recorder.Code)
	}
}

// AuthenticateAnyClient is what /userinfo uses; it must accept a third-party token
// that Authenticate rejects.
func TestAuthenticateAnyClientAcceptsThirdPartyToken(t *testing.T) {
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)
	token := signTestToken(t, manager, auth.TokenInput{
		Subject: "42", JTI: "jti-42", Role: "member", State: "on_sast", TokenVersion: 7,
		Scopes: []string{"openid"}, TTL: time.Hour, AuthorizedParty: "some-third-party-app",
	})
	authenticator := Authenticator{
		JWT: manager, Tokens: validStates(now), Clock: testClock{value: now},
		InternalClientID: testInternalClientID,
	}
	principal, err := authenticator.AuthenticateAnyClient(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("AuthenticateAnyClient() error = %v, want success", err)
	}
	if principal.ClientID != "some-third-party-app" {
		t.Fatalf("principal.ClientID = %q, want the third-party client", principal.ClientID)
	}
	if _, err := authenticator.Authenticate(context.Background(), "Bearer "+token); err == nil {
		t.Fatal("Authenticate() accepted a third-party token")
	}
}

// testDelegatedClientID is an arbitrary third-party client_id. Nothing in the
// middleware knows this value — delegation is proven by the token's admin scope, not
// by its azp — so the tests below use it only to show that an azp is present.
const testDelegatedClientID = "ops-tool-delegate"

// performAdminAuthRequest drives RequireAdminAuth followed by RequireDelegatedScope,
// mirroring how the /admin group is wired, so the two gates are exercised in the
// order production uses them.
func performAdminAuthRequest(
	manager *auth.JWTManager, states *fakeAccessStates, now time.Time,
	internalClientID string, allowedScopes []string, header string,
) (*httptest.ResponseRecorder, envelope, bool) {
	router := gin.New()
	authenticator := Authenticator{
		JWT: manager, Tokens: states, Clock: testClock{value: now},
		InternalClientID: internalClientID,
	}
	reached := false
	router.GET("/admin/probe",
		authenticator.RequireAdminAuth(),
		authenticator.RequireDelegatedScope(allowedScopes...),
		func(c *gin.Context) {
			reached = true
			c.JSON(http.StatusOK, envelope{Code: 0, Message: "ok"})
		})
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/probe", nil)
	if header != "" {
		request.Header.Set("Authorization", header)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	var body envelope
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder, body, reached
}

func signAdminToken(t *testing.T, manager *auth.JWTManager, azp string, scopes []string) string {
	t.Helper()
	return signTestToken(t, manager, auth.TokenInput{
		Subject: "42", JTI: "jti-42", Role: "admin", State: "on_sast", TokenVersion: 7,
		Scopes: scopes, TTL: time.Hour, AuthorizedParty: azp,
	})
}

// A third-party token reaches /admin only with an admin scope, and only the scope the
// route asks for. Everything else about the token is identical across rows, so the
// scope set and the azp are the only variables.
func TestRequireAdminAuthAndDelegatedScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)

	tests := []struct {
		name        string
		azp         string
		tokenScopes []string
		allowed     []string
		wantStatus  int
		wantCode    int
		wantHandler bool
	}{
		{
			name: "delegated client with admin:read reaches a read route",
			azp:  testDelegatedClientID, tokenScopes: []string{"openid", scope.AdminRead},
			allowed: []string{scope.AdminRead, scope.AdminWrite}, wantStatus: http.StatusOK, wantHandler: true,
		},
		{
			// write implies read: a write-scoped token must not be locked out of reads.
			name: "delegated client with admin:write reaches a read route",
			azp:  testDelegatedClientID, tokenScopes: []string{"openid", scope.AdminWrite},
			allowed: []string{scope.AdminRead, scope.AdminWrite}, wantStatus: http.StatusOK, wantHandler: true,
		},
		{
			name: "delegated client with admin:read cannot reach a write route",
			azp:  testDelegatedClientID, tokenScopes: []string{"openid", scope.AdminRead},
			allowed: []string{scope.AdminWrite}, wantStatus: http.StatusForbidden, wantCode: errcode.CodeForbidden,
		},
		{
			// Rejected by RequireAdminAuth, before any scope check.
			name: "delegated client without an admin scope is refused entry",
			azp:  testDelegatedClientID, tokenScopes: []string{"openid"},
			allowed: []string{scope.AdminRead, scope.AdminWrite}, wantStatus: http.StatusForbidden, wantCode: errcode.CodeForbidden,
		},
		{
			// The delegate is not named anywhere: any third-party client holding an admin
			// scope is admitted, because only a registration an operator granted that scope
			// can produce such a token. This is what lets a second ops tool be onboarded
			// through the console instead of through a migration.
			name: "any third-party client holding admin:write is admitted",
			azp:  "some-other-app", tokenScopes: []string{"openid", scope.AdminWrite},
			allowed: []string{scope.AdminWrite}, wantStatus: http.StatusOK, wantHandler: true,
		},
		{
			// The companion to the row above: without an admin scope an arbitrary
			// third-party token is still refused outright, so widening the delegate set did
			// not widen what an ordinary third-party token may reach.
			name: "an arbitrary third-party client without an admin scope is refused",
			azp:  "some-other-app", tokenScopes: []string{"openid", "profile", "email"},
			allowed:    []string{scope.AdminRead, scope.AdminWrite},
			wantStatus: http.StatusForbidden, wantCode: errcode.CodeForbidden,
		},
		{
			// The console holds only session scopes and must stay exempt from the scope gate.
			name: "internal console token passes both gates",
			azp:  testInternalClientID, tokenScopes: []string{"openid", "profile", "email"},
			allowed: []string{scope.AdminWrite}, wantStatus: http.StatusOK, wantHandler: true,
		},
		{
			// An azp-less token predates the claim and is only ever the built-in client's.
			name: "legacy token without azp passes both gates",
			azp:  "", tokenScopes: []string{"openid"},
			allowed: []string{scope.AdminWrite}, wantStatus: http.StatusOK, wantHandler: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signAdminToken(t, manager, test.azp, test.tokenScopes)
			recorder, body, reached := performAdminAuthRequest(manager, validStates(now), now,
				testInternalClientID, test.allowed, "Bearer "+token)
			if recorder.Code != test.wantStatus || reached != test.wantHandler {
				t.Fatalf("status = %d (handler reached %v), want %d (%v): %#v",
					recorder.Code, reached, test.wantStatus, test.wantHandler, body)
			}
			if test.wantCode != 0 && body.Code != test.wantCode {
				t.Fatalf("body.Code = %d, want %d", body.Code, test.wantCode)
			}
		})
	}
}

// An unset InternalClientID must fail closed on the admin path too. Were the
// delegated branch evaluated first, a deployment missing this value would admit
// every admin-scoped third-party token instead of refusing all of them.
func TestRequireAdminAuthFailsClosedWithoutInternalClientID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)
	token := signAdminToken(t, manager, testDelegatedClientID, []string{"openid", scope.AdminWrite})

	recorder, _, reached := performAdminAuthRequest(manager, validStates(now), now,
		"", []string{scope.AdminWrite}, "Bearer "+token)
	if recorder.Code != http.StatusInternalServerError || reached {
		t.Fatalf("status = %d (handler reached %v), want 500 and no handler", recorder.Code, reached)
	}
}

// An empty allowed set must deny, mirroring RequireRole: a route wired without a
// scope must be a visible 403, not an endpoint that accepts anything.
func TestRequireDelegatedScopeFailsClosedOnEmptyAllowedSet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)
	token := signAdminToken(t, manager, testDelegatedClientID, []string{"openid", scope.AdminWrite})

	recorder, body, reached := performAdminAuthRequest(manager, validStates(now), now,
		testInternalClientID, nil, "Bearer "+token)
	if recorder.Code != http.StatusForbidden || body.Code != errcode.CodeForbidden || reached {
		t.Fatalf("status = %d %#v (handler reached %v), want 403 and no handler", recorder.Code, body, reached)
	}
}

// RequireDelegatedScope reads the Principal that RequireAdminAuth sets; without it
// the two are chained in the wrong order, which is a wiring bug rather than a
// permission denial.
func TestRequireDelegatedScopeWithoutPrincipalIsInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	authenticator := Authenticator{InternalClientID: testInternalClientID}
	reached := false
	router.GET("/admin/probe", authenticator.RequireDelegatedScope(scope.AdminRead), func(c *gin.Context) {
		reached = true
		c.Status(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/admin/probe", nil))
	if recorder.Code != http.StatusInternalServerError || reached {
		t.Fatalf("status = %d (handler reached %v), want 500 and no handler", recorder.Code, reached)
	}
}

// testUserClientID is an arbitrary first-party client_id. Nothing in the
// middleware knows this value — self-service access is proven by the token's user
// scope, which only a first-party registration an operator granted that scope can
// produce — so the tests below use it only to show that a non-console azp is
// present.
const testUserClientID = "sast-people"

// performUserAuthRequest drives RequireUserAuth followed by RequireDelegatedScope,
// mirroring how the /user group is wired, so the two gates are exercised in the
// order production uses them.
func performUserAuthRequest(
	manager *auth.JWTManager, states *fakeAccessStates, now time.Time,
	internalClientID string, allowedScopes []string, header string,
) (*httptest.ResponseRecorder, envelope, bool) {
	router := gin.New()
	authenticator := Authenticator{
		JWT: manager, Tokens: states, Clock: testClock{value: now},
		InternalClientID: internalClientID,
	}
	reached := false
	router.GET("/user/probe",
		authenticator.RequireUserAuth(),
		authenticator.RequireDelegatedScope(allowedScopes...),
		func(c *gin.Context) {
			reached = true
			c.JSON(http.StatusOK, envelope{Code: 0, Message: "ok"})
		})
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/user/probe", nil)
	if header != "" {
		request.Header.Set("Authorization", header)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	var body envelope
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder, body, reached
}

func signUserToken(t *testing.T, manager *auth.JWTManager, azp string, scopes []string) string {
	t.Helper()
	return signTestToken(t, manager, auth.TokenInput{
		Subject: "42", JTI: "jti-42", Role: "on_sast", State: "on_sast", TokenVersion: 7,
		Scopes: scopes, TTL: time.Hour, AuthorizedParty: azp,
	})
}

// A self-service token reaches /user only with a user scope, and only the scope
// the route asks for. A third-party token is refused at RequireUserAuth even if it
// carries an admin scope — the user surface is gated by user scopes alone.
func TestRequireUserAuthAndDelegatedScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)

	tests := []struct {
		name        string
		azp         string
		tokenScopes []string
		allowed     []string
		wantStatus  int
		wantCode    int
		wantHandler bool
	}{
		{
			name: "first-party client with user:read reaches a read route",
			azp:  testUserClientID, tokenScopes: []string{"openid", scope.UserRead},
			allowed: []string{scope.UserRead, scope.UserWrite}, wantStatus: http.StatusOK, wantHandler: true,
		},
		{
			// write implies read: a write-scoped token must not be locked out of reads.
			name: "first-party client with user:write reaches a read route",
			azp:  testUserClientID, tokenScopes: []string{"openid", scope.UserWrite},
			allowed: []string{scope.UserRead, scope.UserWrite}, wantStatus: http.StatusOK, wantHandler: true,
		},
		{
			name: "first-party client with user:read cannot reach a write route",
			azp:  testUserClientID, tokenScopes: []string{"openid", scope.UserRead},
			allowed: []string{scope.UserWrite}, wantStatus: http.StatusForbidden, wantCode: errcode.CodeForbidden,
		},
		{
			// Rejected by RequireUserAuth, before any scope check.
			name: "first-party client without a user scope is refused entry",
			azp:  testUserClientID, tokenScopes: []string{"openid", "profile", "email"},
			allowed: []string{scope.UserRead, scope.UserWrite}, wantStatus: http.StatusForbidden, wantCode: errcode.CodeForbidden,
		},
		{
			// An admin-scoped token is a third-party delegation credential and must not
			// reach the user surface: the two scope families gate disjoint routes.
			name: "admin-scoped token cannot reach the user surface",
			azp:  testDelegatedClientID, tokenScopes: []string{"openid", scope.AdminWrite},
			allowed: []string{scope.UserRead, scope.UserWrite}, wantStatus: http.StatusForbidden, wantCode: errcode.CodeForbidden,
		},
		{
			name: "an arbitrary third-party token without a user scope is refused",
			azp:  "some-other-app", tokenScopes: []string{"openid", "profile", "email"},
			allowed:    []string{scope.UserRead, scope.UserWrite},
			wantStatus: http.StatusForbidden, wantCode: errcode.CodeForbidden,
		},
		{
			// The console holds only session scopes and must stay exempt from the scope gate.
			name: "internal console token passes both gates",
			azp:  testInternalClientID, tokenScopes: []string{"openid", "profile", "email"},
			allowed: []string{scope.UserWrite}, wantStatus: http.StatusOK, wantHandler: true,
		},
		{
			// An azp-less token predates the claim and is only ever the built-in client's.
			name: "legacy token without azp passes both gates",
			azp:  "", tokenScopes: []string{"openid"},
			allowed: []string{scope.UserWrite}, wantStatus: http.StatusOK, wantHandler: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signUserToken(t, manager, test.azp, test.tokenScopes)
			recorder, body, reached := performUserAuthRequest(manager, validStates(now), now,
				testInternalClientID, test.allowed, "Bearer "+token)
			if recorder.Code != test.wantStatus || reached != test.wantHandler {
				t.Fatalf("status = %d (handler reached %v), want %d (%v): %#v",
					recorder.Code, reached, test.wantStatus, test.wantHandler, body)
			}
			if test.wantCode != 0 && body.Code != test.wantCode {
				t.Fatalf("body.Code = %d, want %d", body.Code, test.wantCode)
			}
		})
	}
}

// An unset InternalClientID must fail closed on the /user path too, mirroring the
// admin path: without it, a deployment could not distinguish the console from a
// scoped client and would admit none of them safely.
func TestRequireUserAuthFailsClosedWithoutInternalClientID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)
	token := signUserToken(t, manager, testUserClientID, []string{"openid", scope.UserRead})

	recorder, _, reached := performUserAuthRequest(manager, validStates(now), now,
		"", []string{scope.UserRead}, "Bearer "+token)
	if recorder.Code != http.StatusInternalServerError || reached {
		t.Fatalf("status = %d (handler reached %v), want 500 and no handler", recorder.Code, reached)
	}
}
