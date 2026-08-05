package oauthhandler_test

// End-to-end coverage for the authorization code flow: real HTTP requests through
// the handler and service layers onto a real PostgreSQL and a real Redis.
//
// The three layers each have their own tests with the layer below faked, so what
// is only observable here is the wiring between them — a stash written by one
// endpoint and read by another, a code row whose family the token endpoint
// actually revokes, and a JWT this service's own middleware accepts. A contract
// mismatch across a seam passes every unit test and fails only here.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	oauthredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/oauth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/migration"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/oauthhandler"
)

const (
	e2eConsentURL  = "https://link.sast.fun/oauth/consent"
	e2eRedirectURI = "https://rp.example.test/callback"
	e2eClientID    = "e2e-third-party"
	e2eVerifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	e2eIssuer      = "https://link.sast.fun/v2"
)

// e2eSecret is the confidential client's secret for this test's throwaway
// database, not a real credential.
const e2eSecret = "e2e-client-secret-value-32-bytes" // #nosec G101 -- test fixture

type e2eHarness struct {
	router   *gin.Engine
	service  oauth.Service
	tokens   *repository.TokenRepository
	database *gorm.DB
	user     *model.User
	client   *model.OAuthClient
	jwt      *auth.JWTManager
	store    internalredis.Store
}

func setupE2E(t *testing.T) *e2eHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)

	databaseURL := testutil.StartPostgres(t)
	instance, err := migration.New(databaseURL)
	if err != nil {
		t.Fatalf("create migration: %v", err)
	}
	t.Cleanup(func() { _, _ = instance.Close() })
	if migrateErr := instance.Up(); migrateErr != nil {
		t.Fatalf("apply migrations: %v", migrateErr)
	}
	database := testutil.OpenGORM(t, databaseURL)
	store := internalredis.Store{
		Client: testutil.StartRedis(t),
		Keys:   internalredis.NewKeys("sastlink:e2e"),
	}

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	jwtManager := &auth.JWTManager{
		Issuer:   e2eIssuer,
		Audience: []string{"sast-link-v2"},
		Active:   auth.JWTKeyPair{KID: "e2e", Private: key},
	}
	refreshManager, err := auth.NewRefreshTokenManager("0123456789abcdef0123456789abcdef", nil)
	if err != nil {
		t.Fatalf("construct refresh manager: %v", err)
	}

	users := repository.NewUser(database)
	user := &model.User{
		Name:         "端到端用户",
		PhoneNumber:  "13800138001",
		QQNumber:     "10001",
		PasswordHash: "password-hash",
		LoginEmail:   "e2e-oauth@njupt.edu.cn",
		StudentID:    "B24040199",
		Role:         model.UserRoleMember,
		State:        model.UserStateOnSAST,
		EmailType:    model.EmailTypeNJUpt,
		College:      model.CollegeOther,
	}
	nickname := "小端"
	if err := users.CreateWithProfile(context.Background(), user, &model.Profile{Nickname: &nickname}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// A confidential third-party client, so client_secret authentication is on the
	// path here. It is the branch production cannot reach yet (no registration API),
	// which makes it the one most worth covering end to end.
	secretHash := auth.HashClientSecret(e2eSecret)
	client := &model.OAuthClient{
		ClientID:         e2eClientID,
		ClientName:       "E2E Third Party",
		ClientSecretHash: &secretHash,
		ClientType:       model.ClientTypeThirdParty,
		RedirectURIs:     model.StringArray{e2eRedirectURI},
		GrantTypes:       model.StringArray{"authorization_code", "refresh_token"},
		Scopes:           model.StringArray{"openid", "profile", "email"},
	}
	if err := database.Create(client).Error; err != nil {
		t.Fatalf("create OAuth client: %v", err)
	}

	tokens := repository.NewToken(database)
	service := oauth.Service{
		Users:          users,
		Clients:        repository.NewOAuthClient(database),
		Authorizations: repository.NewOAuthAuthorization(database),
		Tokens:         tokens,
		Audit:          repository.NewAuditLog(database),
		Profiles:       users,
		Requests:       oauthredis.AuthorizeRequestStore{Store: store},
		Blacklist:      oauthredis.BlacklistStore{Store: store},
		JWT:            jwtManager,
		RefreshTokens:  refreshManager,
		AccessTTL:      time.Hour,
		RefreshTTL:     30 * 24 * time.Hour,
		CodeTTL:        5 * time.Minute,
		RequestTTL:     10 * time.Minute,
		Issuer:         e2eIssuer,
	}

	router := gin.New()
	oauthhandler.RegisterRoutes(router, oauthhandler.Handler{
		Service:    service,
		Auth:       middleware.Authenticator{JWT: jwtManager, Tokens: tokens},
		ConsentURL: e2eConsentURL,
	}, func(c *gin.Context) {
		// The consent endpoint's own middleware is not under test here; the flow needs
		// an authenticated principal, which the real JWT path already covers elsewhere.
		middleware.SetPrincipal(c, middleware.Principal{UserID: user.ID, JTI: "e2e-consent"})
		c.Next()
	})

	return &e2eHarness{
		router: router, service: service, tokens: tokens, database: database,
		user: user, client: client, jwt: jwtManager, store: store,
	}
}

func (h *e2eHarness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	h.router.ServeHTTP(recorder, request)
	return recorder
}

func (h *e2eHarness) postForm(t *testing.T, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.router.ServeHTTP(recorder, request)
	return recorder
}

func (h *e2eHarness) postJSON(t *testing.T, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	h.router.ServeHTTP(recorder, request)
	return recorder
}

// authorizeAndConsent walks both legs and returns the issued authorization code.
func (h *e2eHarness) authorizeAndConsent(t *testing.T, scopeValue string) string {
	t.Helper()
	challenge, err := auth.PKCEChallengeS256(e2eVerifier)
	if err != nil {
		t.Fatalf("compute challenge: %v", err)
	}
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {e2eClientID},
		"redirect_uri":          {e2eRedirectURI},
		"scope":                 {scopeValue},
		"state":                 {"e2e-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"nonce":                 {"e2e-nonce"},
	}
	recorder := h.get(t, "/oauth/authorize?"+query.Encode())
	if recorder.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302: %s", recorder.Code, recorder.Body.String())
	}
	consentQuery := mustParseQuery(t, recorder.Header().Get("Location"))
	requestID := consentQuery.Get("request_id")
	if requestID == "" {
		t.Fatalf("authorize redirect carries no request_id: %s", recorder.Header().Get("Location"))
	}

	consent := h.postJSON(t, "/oauth/authorize/consent",
		`{"request_id":"`+requestID+`","approve":true}`)
	if consent.Code != http.StatusOK {
		t.Fatalf("consent status = %d, want 200: %s", consent.Code, consent.Body.String())
	}
	var body struct {
		Data struct {
			RedirectURI string `json:"redirect_uri"`
		} `json:"data"`
	}
	if err := json.Unmarshal(consent.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode consent body: %v", err)
	}
	clientQuery := mustParseQuery(t, body.Data.RedirectURI)
	code := clientQuery.Get("code")
	if code == "" {
		t.Fatalf("consent redirect carries no code: %s", body.Data.RedirectURI)
	}
	if clientQuery.Get("state") != "e2e-state" {
		t.Fatalf("state = %q, want the original value", clientQuery.Get("state"))
	}
	return code
}

func mustParseQuery(t *testing.T, rawURL string) url.Values {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return parsed.Query()
}

type e2eTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

func (h *e2eHarness) redeem(t *testing.T, code string) (*e2eTokenResponse, *httptest.ResponseRecorder) {
	t.Helper()
	recorder := h.postForm(t, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {e2eRedirectURI},
		"client_id":     {e2eClientID},
		"client_secret": {e2eSecret},
		"code_verifier": {e2eVerifier},
	})
	if recorder.Code != http.StatusOK {
		return nil, recorder
	}
	var body e2eTokenResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode token body: %v", err)
	}
	return &body, recorder
}

func TestE2EAuthorizationCodeFlow(t *testing.T) {
	testutil.RequireProvider(t)
	h := setupE2E(t)

	code := h.authorizeAndConsent(t, "openid profile email")
	tokenResponse, recorder := h.redeem(t, code)
	if tokenResponse == nil {
		t.Fatalf("token status = %d: %s", recorder.Code, recorder.Body.String())
	}
	if tokenResponse.TokenType != "Bearer" || tokenResponse.ExpiresIn != 3600 {
		t.Fatalf("token response = %+v", tokenResponse)
	}
	if tokenResponse.Scope != "openid profile email" {
		t.Fatalf("scope = %q, want the granted set", tokenResponse.Scope)
	}
	if tokenResponse.IDToken == "" || tokenResponse.RefreshToken == "" {
		t.Fatalf("token response = %+v, want an ID token and a refresh token", tokenResponse)
	}

	// The access token must be accepted by this service's own middleware, which is
	// what /userinfo authenticates with. A wrong audience or a missing DB row would
	// only surface here.
	userInfo := h.getUserInfo(t, tokenResponse.AccessToken)
	if userInfo["sub"] != mustSubject(h.user.ID) {
		t.Fatalf("userinfo sub = %v, want %q", userInfo["sub"], mustSubject(h.user.ID))
	}
	if userInfo["preferred_username"] != "小端" {
		t.Fatalf("preferred_username = %v, want the profile nickname", userInfo["preferred_username"])
	}
	if userInfo["email"] != "e2e-oauth@njupt.edu.cn" || userInfo["email_verified"] != true {
		t.Fatalf("userinfo email claims = %v", userInfo)
	}

	// Rotation must work against the persisted family.
	rotated := h.postForm(t, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenResponse.RefreshToken},
		"client_id":     {e2eClientID},
		"client_secret": {e2eSecret},
	})
	if rotated.Code != http.StatusOK {
		t.Fatalf("refresh status = %d: %s", rotated.Code, rotated.Body.String())
	}
	var rotatedBody e2eTokenResponse
	if err := json.Unmarshal(rotated.Body.Bytes(), &rotatedBody); err != nil {
		t.Fatalf("decode rotated body: %v", err)
	}
	if rotatedBody.RefreshToken == tokenResponse.RefreshToken {
		t.Fatal("rotation returned the same refresh token")
	}
}

func (h *e2eHarness) getUserInfo(t *testing.T, accessToken string) map[string]any {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+accessToken)
	h.router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("userinfo status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var claims map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &claims); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	return claims
}

func mustSubject(userID int64) string {
	return strconv.FormatInt(userID, 10)
}

// Replaying a code must revoke the family it already produced, so the access token
// from the first redemption stops working against the real middleware and lands in
// the real Redis blacklist.
func TestE2ECodeReplayRevokesIssuedTokens(t *testing.T) {
	testutil.RequireProvider(t)
	h := setupE2E(t)

	code := h.authorizeAndConsent(t, "openid profile")
	first, recorder := h.redeem(t, code)
	if first == nil {
		t.Fatalf("first redemption failed: %d %s", recorder.Code, recorder.Body.String())
	}
	// Confirm the token works before the replay, so the assertion after it is about
	// the revocation rather than a token that never worked.
	h.getUserInfo(t, first.AccessToken)

	_, replay := h.redeem(t, code)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400: %s", replay.Code, replay.Body.String())
	}

	claims, err := h.jwt.VerifyAccessToken(first.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	// The DB is authoritative: the row must be revoked.
	access, err := h.tokens.FindAccessTokenByJTI(context.Background(), claims.ID)
	if err != nil {
		t.Fatalf("FindAccessTokenByJTI: %v", err)
	}
	if access.RevokedAt == nil {
		t.Fatal("access token row is not revoked after the code replay")
	}
	// The revocation must have invalidated the auth-state cache entry, so the
	// middleware cannot admit the replayed token's cached state.
	if _, found, err := h.store.GetAuthState(context.Background(), claims.ID); err != nil {
		t.Fatalf("GetAuthState: %v", err)
	} else if found {
		t.Fatal("revoked JTI's auth-state cache entry was not invalidated")
	}
	// The middleware must now reject it.
	recorder = httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+first.AccessToken)
	h.router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo after revocation = %d, want 401", recorder.Code)
	}
}

// The stash lives in Redis and the code row in PostgreSQL; a single authorize
// request must not be convertible into two codes even under concurrent consent.
func TestE2EConcurrentConsentYieldsOneCode(t *testing.T) {
	testutil.RequireProvider(t)
	h := setupE2E(t)

	challenge, err := auth.PKCEChallengeS256(e2eVerifier)
	if err != nil {
		t.Fatalf("compute challenge: %v", err)
	}
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {e2eClientID},
		"redirect_uri":          {e2eRedirectURI},
		"scope":                 {"openid"},
		"state":                 {"e2e-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	recorder := h.get(t, "/oauth/authorize?"+query.Encode())
	requestID := mustParseQuery(t, recorder.Header().Get("Location")).Get("request_id")

	const contenders = 6
	type outcome struct {
		status int
		body   string
	}
	results := make(chan outcome, contenders)
	start := make(chan struct{})
	for range contenders {
		go func() {
			<-start
			response := h.postJSON(t, "/oauth/authorize/consent",
				`{"request_id":"`+requestID+`","approve":true}`)
			results <- outcome{status: response.Code, body: response.Body.String()}
		}()
	}
	close(start)

	successes := 0
	for range contenders {
		result := <-results
		if result.status == http.StatusOK {
			successes++
			continue
		}
		if result.status != http.StatusBadRequest {
			t.Fatalf("unexpected consent status %d: %s", result.status, result.body)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent consent successes = %d, want exactly 1", successes)
	}
}

// Revocation must cut the whole family across both stores.
func TestE2ERevokeEndsTheSession(t *testing.T) {
	testutil.RequireProvider(t)
	h := setupE2E(t)

	code := h.authorizeAndConsent(t, "openid")
	pair, recorder := h.redeem(t, code)
	if pair == nil {
		t.Fatalf("redemption failed: %d %s", recorder.Code, recorder.Body.String())
	}

	revoke := h.postForm(t, "/oauth/revoke", url.Values{
		"token":         {pair.RefreshToken},
		"client_id":     {e2eClientID},
		"client_secret": {e2eSecret},
	})
	if revoke.Code != http.StatusOK || revoke.Body.Len() != 0 {
		t.Fatalf("revoke = %d %q, want an empty 200", revoke.Code, revoke.Body.String())
	}

	// The sibling access token must be dead, not merely the presented refresh token.
	after := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	h.router.ServeHTTP(after, request)
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo after revoke = %d, want 401", after.Code)
	}

	// A second revoke of the same token is still a success (RFC 7009 §2.2).
	again := h.postForm(t, "/oauth/revoke", url.Values{
		"token":         {pair.RefreshToken},
		"client_id":     {e2eClientID},
		"client_secret": {e2eSecret},
	})
	if again.Code != http.StatusOK {
		t.Fatalf("second revoke = %d, want 200", again.Code)
	}
}

// Discovery must describe endpoints that exist, and JWKS must verify the tokens
// this deployment actually issues.
func TestE2EDiscoveryMatchesRuntime(t *testing.T) {
	testutil.RequireProvider(t)
	h := setupE2E(t)

	recorder := h.get(t, "/.well-known/openid-configuration")
	var document map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if document["issuer"] != e2eIssuer {
		t.Fatalf("issuer = %v, want %q", document["issuer"], e2eIssuer)
	}
	// Every advertised endpoint must be a registered route.
	registered := map[string]bool{}
	for _, route := range h.router.Routes() {
		registered[route.Path] = true
	}
	for _, key := range []string{
		"authorization_endpoint", "token_endpoint", "userinfo_endpoint",
		"jwks_uri", "revocation_endpoint",
	} {
		raw, _ := document[key].(string)
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%s = %q is not a URL", key, raw)
		}
		path := strings.TrimPrefix(parsed.Path, "/v2")
		if !registered[path] {
			t.Fatalf("%s advertises %q, which is not a registered route", key, path)
		}
	}

	jwks := h.get(t, "/.well-known/jwks.json")
	var keySet struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(jwks.Body.Bytes(), &keySet); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(keySet.Keys) != 1 || keySet.Keys[0]["kid"] != "e2e" {
		t.Fatalf("jwks = %+v, want the active signing key", keySet.Keys)
	}
}

// Guards against the seam the unit tests cannot see: a schema change that makes the
// service's expectations and the table diverge.
func TestE2EAuditTrailIsWritten(t *testing.T) {
	testutil.RequireProvider(t)
	h := setupE2E(t)

	code := h.authorizeAndConsent(t, "openid")
	if _, recorder := h.redeem(t, code); recorder.Code != http.StatusOK {
		t.Fatalf("redemption failed: %d %s", recorder.Code, recorder.Body.String())
	}

	database := h.databaseHandle(t)
	var actions []string
	if err := database.Model(&model.AuditLog{}).
		Where("resource = ?", "oauth").
		Order("id").
		Pluck("action", &actions).Error; err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(actions) != 2 || actions[0] != "oauth_authorize" || actions[1] != "oauth_token" {
		t.Fatalf("audit actions = %v, want oauth_authorize then oauth_token", actions)
	}
}

func (h *e2eHarness) databaseHandle(t *testing.T) *gorm.DB {
	t.Helper()
	if h.database == nil {
		t.Fatal("harness has no database handle")
	}
	return h.database
}

// A third-party access token must not authenticate on the internal API.
//
// This is the regression test for a real defect: both token kinds carry this
// service as their audience, so before the azp gate an openid-only third-party
// grant authenticated against the internal middleware and yielded a full
// principal — enough to rewrite the profile or bind an attacker's email as a
// login method. The token must still work on /userinfo, which exists to serve it.
func TestE2EThirdPartyTokenIsNotAnInternalSessionCredential(t *testing.T) {
	testutil.RequireProvider(t)
	h := setupE2E(t)

	code := h.authorizeAndConsent(t, "openid")
	pair, recorder := h.redeem(t, code)
	if pair == nil {
		t.Fatalf("redemption failed: %d %s", recorder.Code, recorder.Body.String())
	}

	// The internal middleware, configured exactly as cmd/api does.
	internal := gin.New()
	authenticator := middleware.Authenticator{
		JWT: h.jwt, Tokens: h.tokens, InternalClientID: "sast-link-web",
	}
	internal.GET("/user/profile", authenticator.RequireAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	rejected := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/user/profile", nil)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	internal.ServeHTTP(rejected, request)
	if rejected.Code != http.StatusForbidden {
		t.Fatalf("internal endpoint accepted a third-party token: status %d, want 403", rejected.Code)
	}

	// The same token must still be good at /userinfo.
	claims := h.getUserInfo(t, pair.AccessToken)
	if claims["sub"] != mustSubject(h.user.ID) {
		t.Fatalf("userinfo sub = %v, want %q", claims["sub"], mustSubject(h.user.ID))
	}
}
