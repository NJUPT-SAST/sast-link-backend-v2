package oauthhandler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
)

const testConsentURL = "https://link.sast.fun/oauth/consent"

type fakeService struct {
	authorizeResult   *oauth.AuthorizeResult
	consentResult     *oauth.ConsentResult
	consentInfoResult *oauth.ConsentInfoResult
	tokenResult       *oauth.TokenResult
	userInfoResult    *oauth.UserInfoResult
	authorizeErr      error
	consentErr        error
	consentInfoErr    error
	tokenErr          error
	revokeErr         error
	userInfoErr       error
	authorizeInput    oauth.AuthorizeInput
	consentInput      oauth.ConsentInput
	consentInfoInput  oauth.ConsentInfoInput
	tokenInput        oauth.TokenInput
	revokeInput       oauth.RevokeInput
	userInfoInput     oauth.UserInfoInput
	revokeCalls       int
}

func (s *fakeService) Authorize(_ context.Context, input oauth.AuthorizeInput) (*oauth.AuthorizeResult, error) {
	s.authorizeInput = input
	return s.authorizeResult, s.authorizeErr
}

func (s *fakeService) Consent(_ context.Context, input oauth.ConsentInput) (*oauth.ConsentResult, error) {
	s.consentInput = input
	return s.consentResult, s.consentErr
}

func (s *fakeService) ConsentInfo(_ context.Context, input oauth.ConsentInfoInput) (*oauth.ConsentInfoResult, error) {
	s.consentInfoInput = input
	return s.consentInfoResult, s.consentInfoErr
}

func (s *fakeService) Token(_ context.Context, input oauth.TokenInput) (*oauth.TokenResult, error) {
	s.tokenInput = input
	return s.tokenResult, s.tokenErr
}

func (s *fakeService) Revoke(_ context.Context, input oauth.RevokeInput) error {
	s.revokeInput = input
	s.revokeCalls++
	return s.revokeErr
}

func (s *fakeService) UserInfo(_ context.Context, input oauth.UserInfoInput) (*oauth.UserInfoResult, error) {
	s.userInfoInput = input
	return s.userInfoResult, s.userInfoErr
}

func (s *fakeService) Discovery() map[string]any {
	return map[string]any{"issuer": "https://link.sast.fun/v2"}
}

func (s *fakeService) JWKS() map[string]any {
	return map[string]any{"keys": []map[string]string{{"kid": "active"}}}
}

func (s *fakeService) Grants(_ context.Context, _ int64) ([]repository.OAuthGrant, error) {
	return nil, nil
}

func (s *fakeService) RevokeGrant(_ context.Context, _, _ int64) error {
	return nil
}

type fakeAuthenticator struct {
	principal middleware.Principal
	err       error
	header    string
}

func (a *fakeAuthenticator) AuthenticateAnyClient(_ context.Context, header string) (middleware.Principal, error) {
	a.header = header
	if a.err != nil {
		return middleware.Principal{}, a.err
	}
	return a.principal, nil
}

func newRouter(t *testing.T, service Service, auth Authenticator) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service, Auth: auth, ConsentURL: testConsentURL}, allowAuth())
	return router
}

func allowAuth() gin.HandlerFunc {
	return allowAuthWith(middleware.Principal{UserID: 1, JTI: "jti", Scopes: []string{"openid"}})
}

func allowAuthWith(principal middleware.Principal) gin.HandlerFunc {
	return func(c *gin.Context) {
		middleware.SetPrincipal(c, principal)
		c.Next()
	}
}

func doRequest(t *testing.T, router *gin.Engine, method, target, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	router.ServeHTTP(recorder, request)
	return recorder
}

func decodeJSON(t *testing.T, recorder *httptest.ResponseRecorder, destination any) {
	t.Helper()
	if err := json.NewDecoder(recorder.Body).Decode(destination); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func redirectQuery(t *testing.T, recorder *httptest.ResponseRecorder) (string, url.Values) {
	t.Helper()
	location := recorder.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location %q: %v", location, err)
	}
	return parsed.Scheme + "://" + parsed.Host + parsed.Path, parsed.Query()
}

func TestAuthorizeRedirectsToConsentPage(t *testing.T) {
	service := &fakeService{authorizeResult: &oauth.AuthorizeResult{
		RequestID:  "ar_abc",
		ExpiresIn:  600,
		ClientName: "Third Party App",
		Scopes:     []string{"openid", "profile"},
	}}
	router := newRouter(t, service, &fakeAuthenticator{})

	recorder := doRequest(t, router, http.MethodGet,
		"/oauth/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fapp.test%2Fcb"+
			"&scope=openid+profile&state=xyz&code_challenge=chal&code_challenge_method=S256&nonce=n1", "", "")

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", recorder.Code)
	}
	base, query := redirectQuery(t, recorder)
	if base != testConsentURL {
		t.Fatalf("redirect base = %q, want the consent page", base)
	}
	if query.Get("request_id") != "ar_abc" || query.Get("scope") != "openid profile" {
		t.Fatalf("consent query = %v, want the request ID and scopes", query)
	}

	// Every wire parameter must reach the service unchanged; a dropped one would be
	// silently treated as absent and change the validation outcome.
	input := service.authorizeInput
	if input.ResponseType != "code" || input.ClientID != "app" ||
		input.RedirectURI != "https://app.test/cb" || input.Scope != "openid profile" ||
		input.State != "xyz" || input.CodeChallenge != "chal" ||
		input.CodeChallengeMethod != "S256" || input.Nonce != "n1" {
		t.Fatalf("authorize input = %+v, want every query parameter forwarded", input)
	}
	if input.ClientIP == "" {
		t.Fatal("authorize input carries no client IP; the rate limiter would not key")
	}
}

// The split is the open-redirect defense: an unverified redirect_uri must never
// receive a redirect, verified ones must.
func TestAuthorizeErrorRoutingFollowsRedirectability(t *testing.T) {
	t.Run("non-redirectable error goes to the consent page", func(t *testing.T) {
		service := &fakeService{authorizeErr: &oauth.Error{
			Kind:        oauth.KindInvalidClient,
			Code:        oauth.ErrorInvalidClient,
			Description: "client_id 无效",
		}}
		router := newRouter(t, service, &fakeAuthenticator{})

		recorder := doRequest(t, router, http.MethodGet,
			"/oauth/authorize?client_id=bad&redirect_uri=https%3A%2F%2Fattacker.test%2Fsteal&state=xyz", "", "")

		if recorder.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", recorder.Code)
		}
		base, query := redirectQuery(t, recorder)
		if base != testConsentURL {
			t.Fatalf("redirect base = %q, want the consent page, not the unverified redirect_uri", base)
		}
		if query.Get("error") != oauth.ErrorInvalidClient {
			t.Fatalf("consent error = %q, want invalid_client", query.Get("error"))
		}
		// state must not travel to our own page; it belongs to the client's session.
		if query.Get("state") != "" {
			t.Fatalf("consent query carries state = %q", query.Get("state"))
		}
	})

	t.Run("redirectable error goes to the client", func(t *testing.T) {
		service := &fakeService{authorizeErr: &oauth.Error{
			Kind:         oauth.KindInvalidRequest,
			Code:         oauth.ErrorInvalidScope,
			Description:  "scope 超出注册范围",
			Redirectable: true,
		}}
		router := newRouter(t, service, &fakeAuthenticator{})

		recorder := doRequest(t, router, http.MethodGet,
			"/oauth/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&state=xyz", "", "")

		base, query := redirectQuery(t, recorder)
		if base != "https://app.test/cb" {
			t.Fatalf("redirect base = %q, want the verified client redirect_uri", base)
		}
		if query.Get("error") != oauth.ErrorInvalidScope || query.Get("state") != "xyz" {
			t.Fatalf("client query = %v, want the error and the original state", query)
		}
	})

	// An unrecognized error cannot have its redirectability established, so it must
	// take the safe route.
	t.Run("unknown error is not redirected to the client", func(t *testing.T) {
		service := &fakeService{authorizeErr: context.DeadlineExceeded}
		router := newRouter(t, service, &fakeAuthenticator{})

		recorder := doRequest(t, router, http.MethodGet,
			"/oauth/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&state=xyz", "", "")

		base, query := redirectQuery(t, recorder)
		if base != testConsentURL || query.Get("error") != oauth.ErrorServerError {
			t.Fatalf("redirect = %q %v, want server_error on the consent page", base, query)
		}
	})
}

func TestConsentReturnsEnvelopeWithRedirectURI(t *testing.T) {
	service := &fakeService{consentResult: &oauth.ConsentResult{
		RedirectURI: "https://app.test/cb?code=ac_1&state=xyz",
	}}
	router := newRouter(t, service, &fakeAuthenticator{})

	recorder := doRequest(t, router, http.MethodPost, "/oauth/authorize/consent",
		"application/json", `{"request_id":"ar_abc","approve":true}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var body struct {
		Code int `json:"code"`
		Data struct {
			RedirectURI string `json:"redirect_uri"`
		} `json:"data"`
	}
	decodeJSON(t, recorder, &body)
	if body.Code != 0 || body.Data.RedirectURI != "https://app.test/cb?code=ac_1&state=xyz" {
		t.Fatalf("body = %+v, want the standard envelope carrying the redirect URI", body)
	}
	// The principal must come from the verified token, never from the body.
	if service.consentInput.UserID != 1 || !service.consentInput.Approve {
		t.Fatalf("consent input = %+v, want the authenticated user and approval", service.consentInput)
	}
}

// An omitted approve field must be a bad request rather than an inferred denial:
// a page that fails to send the choice needs fixing, not a guess.
func TestConsentRejectsMissingApproval(t *testing.T) {
	service := &fakeService{}
	router := newRouter(t, service, &fakeAuthenticator{})

	for _, body := range []string{`{"request_id":"ar_abc"}`, `{"approve":true}`, `{"request_id":"ar_abc","approve":true,"extra":1}`} {
		recorder := doRequest(t, router, http.MethodPost, "/oauth/authorize/consent", "application/json", body)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status for %s = %d, want 400", body, recorder.Code)
		}
	}
	if service.consentInput.RequestID != "" {
		t.Fatal("a rejected body reached the service")
	}
}

func TestConsentDenialStillRedirects(t *testing.T) {
	service := &fakeService{consentResult: &oauth.ConsentResult{
		RedirectURI: "https://app.test/cb?error=access_denied&state=xyz",
	}}
	router := newRouter(t, service, &fakeAuthenticator{})

	recorder := doRequest(t, router, http.MethodPost, "/oauth/authorize/consent",
		"application/json", `{"request_id":"ar_abc","approve":false}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with the denial redirect", recorder.Code)
	}
	if service.consentInput.Approve {
		t.Fatal("approve=false was forwarded as true")
	}
}

func TestConsentInfoReturnsVerifiedClientMetadata(t *testing.T) {
	service := &fakeService{consentInfoResult: &oauth.ConsentInfoResult{
		ClientName: "SAST Link Web",
		Scopes:     []string{"openid", "profile"},
		ExpiresIn:  600,
	}}
	router := newRouter(t, service, &fakeAuthenticator{})

	recorder := doRequest(t, router, http.MethodGet, "/oauth/authorize/consent?request_id=ar_abc", "", "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var body struct {
		Code int `json:"code"`
		Data struct {
			ClientName string   `json:"client_name"`
			Scopes     []string `json:"scopes"`
			ExpiresIn  int      `json:"expires_in"`
		} `json:"data"`
	}
	decodeJSON(t, recorder, &body)
	if body.Code != 0 || body.Data.ClientName != "SAST Link Web" || body.Data.ExpiresIn != 600 {
		t.Fatalf("body = %+v, want the verified client metadata", body)
	}
	if service.consentInfoInput.RequestID != "ar_abc" || service.consentInfoInput.UserID != 1 {
		t.Fatalf("consent info input = %+v, want request_id from the query and the principal's user id", service.consentInfoInput)
	}
}

func TestConsentInfoMapsErrorsToBusinessCodes(t *testing.T) {
	service := &fakeService{consentInfoErr: &oauth.Error{
		Kind:        oauth.KindInvalidRequest,
		Code:        oauth.ErrorInvalidRequest,
		Description: "授权请求无效或已过期，请重新发起授权",
	}}
	router := newRouter(t, service, &fakeAuthenticator{})

	recorder := doRequest(t, router, http.MethodGet, "/oauth/authorize/consent?request_id=ar_bad", "", "")

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an invalid request", recorder.Code)
	}
}

func TestConsentMapsErrorsToBusinessCodes(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   int
	}{
		{
			name:       "expired stash",
			err:        &oauth.Error{Kind: oauth.KindInvalidRequest, Code: oauth.ErrorInvalidRequest, Description: "授权请求无效或已过期"},
			wantStatus: http.StatusBadRequest,
			wantCode:   errcode.CodeBadRequest,
		},
		{
			// 404, not the 401 the RFC endpoints give invalid_client: the consent caller is
			// an authenticated human, and it is the third-party client that vanished. 401
			// would send them to re-login, which cannot fix a disabled client. Keeps
			// 40402's {HTTP status}{sequence} convention consistent too.
			name:       "client disabled",
			err:        &oauth.Error{Kind: oauth.KindInvalidClient, Code: oauth.ErrorInvalidClient, Description: "客户端已停用"},
			wantStatus: http.StatusNotFound,
			wantCode:   errcode.CodeClientNotFound,
		},
		{
			name:       "deleted account",
			err:        &oauth.Error{Kind: oauth.KindAccessDenied, Code: oauth.ErrorAccessDenied, Description: "账号已注销"},
			wantStatus: http.StatusForbidden,
			wantCode:   errcode.CodeForbidden,
		},
		{
			name:       "redis outage",
			err:        &oauth.Error{Kind: oauth.KindDependencyUnavailable, Code: oauth.ErrorTemporarilyUnavail, Description: "读取授权请求失败"},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   errcode.CodeDependencyUnavailable,
		},
		{
			name:       "internal fault hides its detail",
			err:        &oauth.Error{Kind: oauth.KindInternal, Code: oauth.ErrorServerError, Description: "pq: relation does not exist"},
			wantStatus: http.StatusInternalServerError,
			wantCode:   errcode.CodeInternal,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeService{consentErr: test.err}
			router := newRouter(t, service, &fakeAuthenticator{})

			recorder := doRequest(t, router, http.MethodPost, "/oauth/authorize/consent",
				"application/json", `{"request_id":"ar_abc","approve":true}`)

			var body struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			decodeJSON(t, recorder, &body)
			if recorder.Code != test.wantStatus || body.Code != test.wantCode {
				t.Fatalf("response = %d/%d, want %d/%d", recorder.Code, body.Code, test.wantStatus, test.wantCode)
			}
			if test.wantCode == errcode.CodeInternal && strings.Contains(body.Message, "relation") {
				t.Fatalf("message = %q, want the internal detail withheld", body.Message)
			}
		})
	}
}

func TestTokenReturnsRFC6749SuccessBody(t *testing.T) {
	service := &fakeService{tokenResult: &oauth.TokenResult{
		AccessToken:  "access-jwt",
		RefreshToken: "rt_value",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "openid profile",
		IDToken:      "id-jwt",
	}}
	router := newRouter(t, service, &fakeAuthenticator{})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"ac_1"},
		"redirect_uri":  {"https://app.test/cb"},
		"client_id":     {"app"},
		"code_verifier": {"verifier"},
	}
	recorder := doRequest(t, router, http.MethodPost, "/oauth/token",
		"application/x-www-form-urlencoded", form.Encode())

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	// RFC 6749 §5.1: a token response must not be cached, or a shared cache could
	// hand one client's tokens to another.
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", recorder.Header().Get("Cache-Control"))
	}
	var body map[string]any
	decodeJSON(t, recorder, &body)
	for key, want := range map[string]any{
		"access_token":  "access-jwt",
		"refresh_token": "rt_value",
		"token_type":    "Bearer",
		"scope":         "openid profile",
		"id_token":      "id-jwt",
	} {
		if body[key] != want {
			t.Fatalf("%s = %v, want %v", key, body[key], want)
		}
	}
	if body["expires_in"] != float64(3600) {
		t.Fatalf("expires_in = %v, want 3600", body["expires_in"])
	}
	// The response must not use the project envelope, which an OAuth client library
	// would not parse.
	if _, present := body["data"]; present {
		t.Fatal("token response is wrapped in the standard envelope")
	}
	if service.tokenInput.GrantType != "authorization_code" || service.tokenInput.Code != "ac_1" ||
		service.tokenInput.CodeVerifier != "verifier" {
		t.Fatalf("token input = %+v, want the form values forwarded", service.tokenInput)
	}
}

func TestTokenRequiresFormEncoding(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		// A JSON body would work here but fail against any conforming server.
		{name: "json body", contentType: "application/json", body: `{"grant_type":"refresh_token"}`},
		{name: "no content type", contentType: "", body: "grant_type=refresh_token"},
		{name: "wrong media type", contentType: "text/plain", body: "grant_type=refresh_token"},
		// RFC 6749 §3.2 forbids repeated parameters; picking one would let a proxy and
		// this server disagree about which value applies.
		{name: "repeated parameter", contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token&grant_type=authorization_code"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeService{}
			router := newRouter(t, service, &fakeAuthenticator{})

			recorder := doRequest(t, router, http.MethodPost, "/oauth/token", test.contentType, test.body)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", recorder.Code)
			}
			var body errorResponse
			decodeJSON(t, recorder, &body)
			if body.Error != oauth.ErrorInvalidRequest {
				t.Fatalf("error = %q, want invalid_request", body.Error)
			}
			if service.tokenInput.GrantType != "" {
				t.Fatal("a rejected body reached the service")
			}
		})
	}
}

// A token request must not be satisfiable by query parameters: those land in
// access logs and browser history, where a code or refresh token must never be.
func TestTokenIgnoresQueryParameters(t *testing.T) {
	service := &fakeService{tokenErr: &oauth.Error{
		Kind: oauth.KindInvalidRequest,
		Code: oauth.ErrorInvalidRequest,
	}}
	router := newRouter(t, service, &fakeAuthenticator{})

	recorder := doRequest(t, router, http.MethodPost,
		"/oauth/token?grant_type=authorization_code&code=ac_leaked",
		"application/x-www-form-urlencoded", "client_id=app")

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if service.tokenInput.GrantType != "" || service.tokenInput.Code != "" {
		t.Fatalf("token input = %+v, want query parameters ignored", service.tokenInput)
	}
}

func TestTokenErrorStatusesFollowRFC6749(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		wantStatus     int
		wantChallenge  bool
		wantRetryAfter string
	}{
		{
			// RFC 6749 §5.2 singles out invalid_client as a 401, but requires a
			// WWW-Authenticate header only when the client authenticated via the
			// Authorization header. This server reads credentials from the form body
			// only and advertises none/client_secret_post, so it must not send a
			// challenge naming an auth scheme it does not implement.
			name:          "invalid client is 401 without a challenge",
			err:           &oauth.Error{Kind: oauth.KindInvalidClient, Code: oauth.ErrorInvalidClient, Description: "客户端认证失败"},
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: false,
		},
		{
			name:       "invalid grant is 400",
			err:        &oauth.Error{Kind: oauth.KindInvalidGrant, Code: oauth.ErrorInvalidGrant, Description: "授权码无效"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unsupported grant type is 400",
			err:        &oauth.Error{Kind: oauth.KindInvalidRequest, Code: oauth.ErrorUnsupportedGrantType},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:           "rate limited is 429 with Retry-After",
			err:            &oauth.Error{Kind: oauth.KindRateLimited, Code: oauth.ErrorTemporarilyUnavail, RetryAfter: 1500 * time.Millisecond},
			wantStatus:     http.StatusTooManyRequests,
			wantRetryAfter: "2",
		},
		{
			name:       "internal is 500",
			err:        &oauth.Error{Kind: oauth.KindInternal, Code: oauth.ErrorServerError},
			wantStatus: http.StatusInternalServerError,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeService{tokenErr: test.err}
			router := newRouter(t, service, &fakeAuthenticator{})

			recorder := doRequest(t, router, http.MethodPost, "/oauth/token",
				"application/x-www-form-urlencoded", "grant_type=refresh_token&client_id=app")

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
			challenge := recorder.Header().Get("WWW-Authenticate")
			if test.wantChallenge && challenge == "" {
				t.Fatal("401 carries no WWW-Authenticate challenge")
			}
			if !test.wantChallenge && challenge != "" {
				t.Fatalf("WWW-Authenticate = %q on a non-401", challenge)
			}
			if got := recorder.Header().Get("Retry-After"); got != test.wantRetryAfter {
				t.Fatalf("Retry-After = %q, want %q", got, test.wantRetryAfter)
			}
		})
	}
}

// An unmapped error must not put its text on the wire: the body is returned to the
// client verbatim and could otherwise carry dependency detail.
func TestTokenHidesUnmappedErrorDetail(t *testing.T) {
	service := &fakeService{tokenErr: context.DeadlineExceeded}
	router := newRouter(t, service, &fakeAuthenticator{})

	recorder := doRequest(t, router, http.MethodPost, "/oauth/token",
		"application/x-www-form-urlencoded", "grant_type=refresh_token&client_id=app")

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	var body errorResponse
	decodeJSON(t, recorder, &body)
	if body.Error != oauth.ErrorServerError || strings.Contains(body.ErrorDescription, "deadline") {
		t.Fatalf("body = %+v, want a generic server_error", body)
	}
}

// RFC 7009 §2.2: success is 200 with an empty body.
func TestRevokeReturnsEmpty200(t *testing.T) {
	service := &fakeService{}
	router := newRouter(t, service, &fakeAuthenticator{})

	form := url.Values{"token": {"rt_value"}, "token_type_hint": {"refresh_token"}, "client_id": {"app"}}
	recorder := doRequest(t, router, http.MethodPost, "/oauth/revoke",
		"application/x-www-form-urlencoded", form.Encode())

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty", recorder.Body.String())
	}
	if service.revokeCalls != 1 || service.revokeInput.Token != "rt_value" ||
		service.revokeInput.TokenTypeHint != "refresh_token" {
		t.Fatalf("revoke input = %+v (%d calls), want the form values forwarded",
			service.revokeInput, service.revokeCalls)
	}
}

func TestRevokeSurfacesClientAuthFailure(t *testing.T) {
	service := &fakeService{revokeErr: &oauth.Error{
		Kind:        oauth.KindInvalidClient,
		Code:        oauth.ErrorInvalidClient,
		Description: "客户端认证失败",
	}}
	router := newRouter(t, service, &fakeAuthenticator{})

	recorder := doRequest(t, router, http.MethodPost, "/oauth/revoke",
		"application/x-www-form-urlencoded", "token=rt_value&client_id=app&client_secret=wrong")

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	var body errorResponse
	decodeJSON(t, recorder, &body)
	if body.Error != oauth.ErrorInvalidClient {
		t.Fatalf("error = %q, want invalid_client", body.Error)
	}
}

func TestUserInfoReturnsClaimsForBothVerbs(t *testing.T) {
	verified := true
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			service := &fakeService{userInfoResult: &oauth.UserInfoResult{
				Subject:       "1",
				Name:          "张三",
				Email:         "b24040101@njupt.edu.cn",
				EmailVerified: &verified,
			}}
			auth := &fakeAuthenticator{principal: middleware.Principal{
				UserID: 1,
				Scopes: []string{"openid", "profile", "email"},
			}}
			router := newRouter(t, service, auth)

			recorder := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(context.Background(), method, "/userinfo", nil)
			request.Header.Set("Authorization", "Bearer token-value")
			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
			}
			var body map[string]any
			decodeJSON(t, recorder, &body)
			if body["sub"] != "1" || body["name"] != "张三" || body["email_verified"] != true {
				t.Fatalf("body = %v, want the claim set at the top level", body)
			}
			// UserInfo is a bare claim set, not an envelope.
			if _, present := body["data"]; present {
				t.Fatal("UserInfo response is wrapped in the standard envelope")
			}
			// The scopes must come from the verified token, so the service can gate on them.
			if len(service.userInfoInput.Scopes) != 3 || service.userInfoInput.UserID != 1 {
				t.Fatalf("userinfo input = %+v, want the principal's ID and scopes", service.userInfoInput)
			}
			if auth.header != "Bearer token-value" {
				t.Fatalf("authenticator saw header %q", auth.header)
			}
		})
	}
}

// RFC 6750 §3: a rejected token gets a Bearer challenge naming the error, which is
// what an OIDC client reads to decide whether to refresh.
func TestUserInfoRejectedTokenUsesBearerChallenge(t *testing.T) {
	service := &fakeService{}
	router := newRouter(t, service, &fakeAuthenticator{err: context.DeadlineExceeded})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/userinfo", nil)
	request.Header.Set("Authorization", "Bearer expired")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	challenge := recorder.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, "Bearer ") || !strings.Contains(challenge, `error="invalid_token"`) {
		t.Fatalf("WWW-Authenticate = %q, want an RFC 6750 Bearer challenge", challenge)
	}
	var body errorResponse
	decodeJSON(t, recorder, &body)
	if body.Error != oauth.ErrorInvalidToken {
		t.Fatalf("error = %q, want invalid_token", body.Error)
	}
	if service.userInfoInput.UserID != 0 {
		t.Fatal("an unauthenticated request reached the service")
	}
}

func TestUserInfoServiceErrorUsesBearerFormat(t *testing.T) {
	service := &fakeService{userInfoErr: &oauth.Error{
		Kind:        oauth.KindInvalidToken,
		Code:        oauth.ErrorInvalidToken,
		Description: "账号已注销",
	}}
	router := newRouter(t, service, &fakeAuthenticator{principal: middleware.Principal{UserID: 1, Scopes: []string{"openid"}}})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/userinfo", nil)
	request.Header.Set("Authorization", "Bearer token")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	if !strings.Contains(recorder.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("WWW-Authenticate = %q", recorder.Header().Get("WWW-Authenticate"))
	}
}

// A missing authenticator is a wiring fault, not a client error; it must not read
// as an invalid token, which would send clients into a refresh loop.
func TestUserInfoWithoutAuthenticatorIsServerError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	RegisterRoutes(router, Handler{Service: &fakeService{}, ConsentURL: testConsentURL}, allowAuth())

	recorder := doRequest(t, router, http.MethodGet, "/userinfo", "", "")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
}

// Only the endpoints that identify the caller from their bearer token may sit
// behind the JWT middleware: the consent step and the signed-in user's own
// authorized-apps view (grants list and revoke). The others are unauthenticated
// by protocol (a browser arriving at /oauth/authorize from a third party carries
// no Authorization header; token/revoke authenticate the client, not a user;
// discovery and JWKS are public) or authenticate inline so they can answer in
// RFC 6750 form (/userinfo). A middleware creeping onto any of them would break
// the flow for every third-party client.
func TestAuthMiddlewareCoversOnlyConsent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	var guarded []string
	marker := func(c *gin.Context) {
		guarded = append(guarded, c.Request.Method+" "+c.FullPath())
		c.Next()
	}
	service := &fakeService{
		authorizeResult: &oauth.AuthorizeResult{RequestID: "ar_1"},
		consentResult:   &oauth.ConsentResult{RedirectURI: "https://app.test/cb"},
		tokenResult:     &oauth.TokenResult{AccessToken: "a", TokenType: "Bearer"},
		userInfoResult:  &oauth.UserInfoResult{Subject: "1"},
	}
	RegisterRoutes(router, Handler{
		Service:    service,
		Auth:       &fakeAuthenticator{principal: middleware.Principal{UserID: 1, Scopes: []string{"openid"}}},
		ConsentURL: testConsentURL,
	}, marker)

	for _, route := range router.Routes() {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(context.Background(), route.Method, route.Path, strings.NewReader(""))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer token")
		router.ServeHTTP(recorder, request)
	}

	want := []string{
		http.MethodGet + " /oauth/authorize/consent",
		http.MethodGet + " /oauth/grants",
		http.MethodPost + " /oauth/authorize/consent",
		http.MethodDelete + " /oauth/grants/:client_id",
	}
	if len(guarded) != len(want) {
		t.Fatalf("middleware covered %v, want %v", guarded, want)
	}
	for i := range want {
		if guarded[i] != want[i] {
			t.Fatalf("middleware covered %v, want %v", guarded, want)
		}
	}
}

func TestDiscoveryAndJWKSAreUnauthenticatedRawJSON(t *testing.T) {
	service := &fakeService{}
	router := newRouter(t, service, &fakeAuthenticator{})

	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/jwks.json"} {
		recorder := doRequest(t, router, http.MethodGet, path, "", "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", path, recorder.Code)
		}
		var body map[string]any
		decodeJSON(t, recorder, &body)
		// Both are protocol documents read by generic OIDC clients, so neither may be
		// wrapped in the project envelope.
		if _, present := body["data"]; present {
			t.Fatalf("%s is wrapped in the standard envelope", path)
		}
	}
}

// A decode failure's description must be one of this package's own messages. The
// text is echoed into an RFC 6749 body and, on 401, into a quoted
// WWW-Authenticate parameter, so a wrapped parser error would put request bytes
// on the wire.
func TestFormErrorDescriptionsAreSelfAuthored(t *testing.T) {
	allowed := map[string]bool{
		"请求 Content-Type 必须为 application/x-www-form-urlencoded": true,
		"请求体不是合法的 urlencoded 表单":                                true,
		"请求包含重复的表单参数":                                           true,
		"请求参数无效":                                                true,
	}
	// A body whose bytes would be visible if any parser error text escaped.
	probe := "grant_type=%zz\"injected"
	for _, target := range []string{"/oauth/token", "/oauth/revoke"} {
		service := &fakeService{}
		router := newRouter(t, service, &fakeAuthenticator{})

		recorder := doRequest(t, router, http.MethodPost, target,
			"application/x-www-form-urlencoded", probe)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", target, recorder.Code)
		}
		var body errorResponse
		decodeJSON(t, recorder, &body)
		if !allowed[body.ErrorDescription] {
			t.Fatalf("%s description = %q, want one of this package's fixed messages",
				target, body.ErrorDescription)
		}
	}
}

// quotedHeaderValue is the structural guard against header injection: a value
// carrying a quote, backslash or CR/LF must not be able to forge another challenge
// parameter or split the header.
//
// A non-conforming description is now dropped rather than emitted in sanitized
// form, so this payload contributes nothing at all — two quoted parameters remain,
// realm and error.
func TestBearerChallengeCannotBeInjected(t *testing.T) {
	challenge := bearerChallenge(&oauth.Error{
		Code:        oauth.ErrorInvalidToken,
		Description: "bad\"token\\, error=\"insufficient_scope\"\r\nX-Injected: yes",
	})
	if strings.ContainsAny(challenge, "\r\n") {
		t.Fatalf("challenge %q contains a line break", challenge)
	}
	// realm and error only — exactly four quotes, all of them ours.
	if got := strings.Count(challenge, `"`); got != 4 {
		t.Fatalf("challenge %q has %d quotes, want 4", challenge, got)
	}
	if strings.Contains(challenge, `\`) {
		t.Fatalf("challenge %q kept a backslash escape", challenge)
	}
	if strings.Contains(challenge, "X-Injected") || strings.Contains(challenge, "insufficient_scope") {
		t.Fatalf("challenge %q leaked payload bytes", challenge)
	}
	if !strings.HasPrefix(challenge, `Bearer realm="sast-link", error="invalid_token"`) {
		t.Fatalf("challenge %q lost its well-formed prefix", challenge)
	}
}

// RFC 6750 §3 limits a quoted challenge value to printable US-ASCII. This
// service's descriptions are Chinese, so they must not reach the header — a client
// validating against the grammar could discard it and lose the error code it needs
// to decide whether to refresh. The body still carries the full message.
func TestBearerChallengeStaysASCII(t *testing.T) {
	service := &fakeService{}
	router := newRouter(t, service, &fakeAuthenticator{err: errors.New("rejected")})

	recorder := doRequest(t, router, http.MethodGet, "/userinfo", "", "")

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	challenge := recorder.Header().Get("WWW-Authenticate")
	if challenge == "" {
		t.Fatal("401 from UserInfo carries no WWW-Authenticate challenge")
	}
	for i := range len(challenge) {
		if challenge[i] < 0x20 || challenge[i] >= 0x7f {
			t.Fatalf("challenge %q carries a non-ASCII or control byte at %d", challenge, i)
		}
	}
	// The error code is the part a client acts on, so it must survive.
	if !strings.Contains(challenge, `error="invalid_token"`) {
		t.Fatalf("challenge %q lost the error code", challenge)
	}
	// The Chinese message still reaches the client, in the body.
	var body errorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.ErrorDescription == "" {
		t.Fatal("body dropped the error description along with the header")
	}
}

// An ASCII description is conforming, so it is emitted rather than dropped.
func TestBearerChallengeKeepsASCIIDescription(t *testing.T) {
	challenge := bearerChallenge(&oauth.Error{
		Code:        oauth.ErrorInvalidToken,
		Description: "token expired",
	})
	if !strings.Contains(challenge, `error_description="token expired"`) {
		t.Fatalf("challenge %q dropped a conforming description", challenge)
	}
}

// An oversized body must produce a clean 400, not a 500 or a hang.
// MaxBytesReader is handed the ResponseWriter and can mark the connection, so this
// checks ParseForm's failure stays an ordinary decode error.
func TestTokenRejectsOversizedBody(t *testing.T) {
	service := &fakeService{}
	router := newRouter(t, service, &fakeAuthenticator{})
	body := "grant_type=refresh_token&refresh_token=" + strings.Repeat("a", 32<<10)

	recorder := doRequest(t, router, http.MethodPost, "/oauth/token",
		"application/x-www-form-urlencoded", body)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
	var response errorResponse
	decodeJSON(t, recorder, &response)
	if response.Error != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", response.Error)
	}
	// The service must not have been reached at all.
	if service.tokenInput != (oauth.TokenInput{}) {
		t.Fatalf("service received %+v for an oversized body", service.tokenInput)
	}
}
