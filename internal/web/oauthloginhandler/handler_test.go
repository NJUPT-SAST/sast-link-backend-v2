package oauthloginhandler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauthlogin"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
)

// fakeService records what the handler passed down and returns canned results.
type fakeService struct {
	authorizeResult *oauthlogin.AuthorizeResult
	authorizeErr    error
	authorizeInput  oauthlogin.AuthorizeInput

	callbackResult *oauthlogin.CallbackResult
	callbackErr    error
	callbackInput  oauthlogin.CallbackInput

	exchangeResult *oauthlogin.ExchangeCodeResult
	exchangeErr    error

	bindResult *oauthlogin.BindResult
	bindErr    error
	bindInput  oauthlogin.BindInput
}

func (s *fakeService) Authorize(
	_ context.Context,
	input oauthlogin.AuthorizeInput,
) (*oauthlogin.AuthorizeResult, error) {
	s.authorizeInput = input
	return s.authorizeResult, s.authorizeErr
}

func (s *fakeService) Callback(
	_ context.Context,
	input oauthlogin.CallbackInput,
) (*oauthlogin.CallbackResult, error) {
	s.callbackInput = input
	return s.callbackResult, s.callbackErr
}

func (s *fakeService) ExchangeCode(
	_ context.Context,
	_ oauthlogin.ExchangeCodeInput,
) (*oauthlogin.ExchangeCodeResult, error) {
	return s.exchangeResult, s.exchangeErr
}

func (s *fakeService) Bind(
	_ context.Context,
	input oauthlogin.BindInput,
) (*oauthlogin.BindResult, error) {
	s.bindInput = input
	return s.bindResult, s.bindErr
}

// newTestRouter mounts the handler with a middleware that injects a principal, so
// the authenticated binding routes are reachable.
func newTestRouter(h Handler, userID int64) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	authMiddleware := func(c *gin.Context) {
		if userID > 0 {
			middleware.SetPrincipal(c, middleware.Principal{UserID: userID})
		}
		c.Next()
	}
	RegisterRoutes(router, h, authMiddleware)
	return router
}

func decodeEnvelope(t *testing.T, body string) (int, string, map[string]any) {
	t.Helper()
	var envelope struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("decode envelope %q: %v", body, err)
	}
	return envelope.Code, envelope.Message, envelope.Data
}

func TestAuthorizeRedirectsToProvider(t *testing.T) {
	service := &fakeService{authorizeResult: &oauthlogin.AuthorizeResult{
		AuthorizeURL: "https://github.test/authorize?state=os_abc",
		State:        "os_abc",
	}}
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/github?redirect=https://link.sast.fun/callback", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", recorder.Code)
	}
	if location := recorder.Header().Get("Location"); location != service.authorizeResult.AuthorizeURL {
		t.Fatalf("Location = %q, want the provider URL", location)
	}
	// The provider comes from the route, not the query, so it cannot be retargeted.
	if service.authorizeInput.Provider != model.LoginMethodGitHub {
		t.Fatalf("provider = %q, want github", service.authorizeInput.Provider)
	}
	if service.authorizeInput.Redirect != "https://link.sast.fun/callback" {
		t.Fatalf("redirect = %q, want the query value", service.authorizeInput.Redirect)
	}
}

func TestAuthorizeLarkRouteUsesLarkProvider(t *testing.T) {
	service := &fakeService{authorizeResult: &oauthlogin.AuthorizeResult{
		AuthorizeURL: "https://lark.test/authorize?state=os_abc",
	}}
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/lark", nil))

	if service.authorizeInput.Provider != model.LoginMethodLark {
		t.Fatalf("provider = %q, want lark", service.authorizeInput.Provider)
	}
}

func TestCallbackBoundRedirectsWithLoginCode(t *testing.T) {
	service := &fakeService{callbackResult: &oauthlogin.CallbackResult{
		Bound:     true,
		LoginCode: "lc_abc123",
		Redirect:  "https://link.sast.fun/callback",
	}}
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/oauth/github/callback?code=provider-code&state=os_abc", nil))

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", recorder.Code)
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := location.Query().Get("code"); got != "lc_abc123" {
		t.Fatalf("code = %q, want lc_abc123", got)
	}
	// A token must never appear in a redirect URL; only the exchangeable code.
	if location.Query().Get("access_token") != "" {
		t.Fatal("the callback redirect carries an access token")
	}
	if service.callbackInput.Code != "provider-code" || service.callbackInput.State != "os_abc" {
		t.Fatalf("service input = %+v, want the query values", service.callbackInput)
	}
}

func TestCallbackUnboundRedirectsWithRegistrationState(t *testing.T) {
	service := &fakeService{callbackResult: &oauthlogin.CallbackResult{
		Bound:             false,
		RegistrationState: "rs_abc123",
		Provider:          "github",
		DisplayName:       "Ptilopsis",
		AvatarURL:         "https://avatars.test/p.png",
		Redirect:          "https://link.sast.fun/callback",
	}}
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/oauth/github/callback?code=provider-code&state=os_abc", nil))

	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	query := location.Query()
	if query.Get("registration_state") != "rs_abc123" {
		t.Fatalf("registration_state = %q", query.Get("registration_state"))
	}
	if query.Get("provider") != "github" {
		t.Fatalf("provider = %q, want github", query.Get("provider"))
	}
	if query.Get("name") != "Ptilopsis" || query.Get("avatar") == "" {
		t.Fatalf("profile hints missing: name=%q avatar=%q", query.Get("name"), query.Get("avatar"))
	}
	// The parked identity stays server-side; only its handle travels.
	if query.Get("provider_id") != "" {
		t.Fatal("the redirect leaks provider_id")
	}
}

func TestCallbackPreservesExistingRedirectQuery(t *testing.T) {
	// A configured redirect may already carry its own query; the login code must
	// be added rather than replacing it.
	service := &fakeService{callbackResult: &oauthlogin.CallbackResult{
		Bound:     true,
		LoginCode: "lc_abc",
		Redirect:  "https://link.sast.fun/callback?next=%2Fdashboard",
	}}
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/oauth/github/callback?code=c&state=s", nil))

	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if location.Query().Get("next") != "/dashboard" {
		t.Fatalf("existing query was dropped: %q", location.RawQuery)
	}
	if location.Query().Get("code") != "lc_abc" {
		t.Fatalf("code missing: %q", location.RawQuery)
	}
}

func TestCallbackFailureRedirectsToErrorPage(t *testing.T) {
	service := &fakeService{callbackErr: &oauthlogin.Error{
		Kind:    oauthlogin.KindForbidden,
		Code:    errcode.CodeLarkTenantRequired,
		Message: "仅限 SAST 成员登录",
	}}
	router := newTestRouter(Handler{
		Service:       service,
		ErrorRedirect: "https://link.sast.fun/oauth/error",
	}, 0)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/oauth/lark/callback?code=c&state=s", nil))

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 to the error page", recorder.Code)
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := location.Query().Get("error"); got != "40302" {
		t.Fatalf("error = %q, want 40302", got)
	}
	if !strings.HasPrefix(location.String(), "https://link.sast.fun/oauth/error") {
		t.Fatalf("Location = %q, want the configured error page", location)
	}
}

func TestCallbackFailureFallsBackToEnvelopeWithoutErrorPage(t *testing.T) {
	service := &fakeService{callbackErr: &oauthlogin.Error{
		Kind: oauthlogin.KindInvalidState,
		Code: errcode.CodeBadRequest,
	}}
	// No ErrorRedirect configured: answering in the envelope is worse UX but
	// never redirects somewhere unvalidated.
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/oauth/github/callback?code=c&state=s", nil))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	code, _, _ := decodeEnvelope(t, recorder.Body.String())
	if code != errcode.CodeBadRequest {
		t.Fatalf("code = %d, want %d", code, errcode.CodeBadRequest)
	}
}

func TestExchangeCodeReturnsTokenPair(t *testing.T) {
	service := &fakeService{exchangeResult: &oauthlogin.ExchangeCodeResult{
		AccessToken:     "access",
		RefreshToken:    "refresh",
		TokenType:       "Bearer",
		AccessExpiresAt: time.Now().Add(time.Hour),
		User: &model.User{
			ID: 42, Name: "Existing", LoginEmail: "existing@sast.fun",
			Role: model.UserRoleFreshman, State: model.UserStateNJUPTer,
		},
	}}
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/exchange-code",
		strings.NewReader(`{"code":"lc_abc"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", recorder.Code, recorder.Body.String())
	}
	code, message, data := decodeEnvelope(t, recorder.Body.String())
	if code != 0 || message != "ok" {
		t.Fatalf("envelope = %d/%q, want 0/ok", code, message)
	}
	if data["access_token"] != "access" || data["token_type"] != "Bearer" {
		t.Fatalf("data = %+v", data)
	}
	// expires_in is relative seconds, per the contract.
	if expiresIn, ok := data["expires_in"].(float64); !ok || expiresIn <= 0 {
		t.Fatalf("expires_in = %v, want a positive number", data["expires_in"])
	}
	user, ok := data["user"].(map[string]any)
	if !ok || user["login_email"] != "existing@sast.fun" {
		t.Fatalf("user = %+v", data["user"])
	}
}

func TestExchangeCodeRejectsMissingCode(t *testing.T) {
	router := newTestRouter(Handler{Service: &fakeService{}}, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/exchange-code",
		strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestExchangeCodeRejectsUnknownFields(t *testing.T) {
	router := newTestRouter(Handler{Service: &fakeService{}}, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/exchange-code",
		strings.NewReader(`{"code":"lc_abc","extra":1}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown field", recorder.Code)
	}
}

func TestExchangeCodeMapsInvalidCodeTo401(t *testing.T) {
	service := &fakeService{exchangeErr: &oauthlogin.Error{
		Kind: oauthlogin.KindInvalidToken,
		Code: errcode.CodeLoginCodeInvalid,
	}}
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/exchange-code",
		strings.NewReader(`{"code":"lc_spent"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	code, _, _ := decodeEnvelope(t, recorder.Body.String())
	if code != errcode.CodeLoginCodeInvalid {
		t.Fatalf("code = %d, want %d", code, errcode.CodeLoginCodeInvalid)
	}
}

func TestBindPassesPrincipalAndProvider(t *testing.T) {
	service := &fakeService{bindResult: &oauthlogin.BindResult{
		Identity: model.Identity{
			ID: 9, UserID: 42, Provider: model.LoginMethodGitHub,
			ProviderID:   "145339646",
			IdentityData: model.JSONB(`{"login":"ptilopsis"}`),
		},
	}}
	router := newTestRouter(Handler{Service: service}, 42)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/user/identities/github?code=provider-code", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", recorder.Code, recorder.Body.String())
	}
	// The caller is identified by the token's principal, never by a request field.
	if service.bindInput.UserID != 42 {
		t.Fatalf("UserID = %d, want 42", service.bindInput.UserID)
	}
	if service.bindInput.Provider != model.LoginMethodGitHub {
		t.Fatalf("provider = %q, want github", service.bindInput.Provider)
	}
	if service.bindInput.Code != "provider-code" {
		t.Fatalf("code = %q, want the query value", service.bindInput.Code)
	}

	_, _, data := decodeEnvelope(t, recorder.Body.String())
	if data["message"] != "GitHub 账号绑定成功" {
		t.Fatalf("message = %v", data["message"])
	}
	identity, ok := data["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity = %+v", data["identity"])
	}
	// identity_data must be a JSON object, not a base64 string.
	identityData, ok := identity["identity_data"].(map[string]any)
	if !ok || identityData["login"] != "ptilopsis" {
		t.Fatalf("identity_data = %+v, want a decoded object", identity["identity_data"])
	}
}

func TestBindLarkUsesLarkMessage(t *testing.T) {
	service := &fakeService{bindResult: &oauthlogin.BindResult{
		Identity: model.Identity{ID: 9, UserID: 42, Provider: model.LoginMethodLark, ProviderID: "on_union"},
	}}
	router := newTestRouter(Handler{Service: service}, 42)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/user/identities/lark?code=provider-code", nil))

	_, _, data := decodeEnvelope(t, recorder.Body.String())
	if data["message"] != "飞书账号绑定成功" {
		t.Fatalf("message = %v", data["message"])
	}
}

func TestBindWithoutPrincipalIs401(t *testing.T) {
	// userID 0 makes the middleware set no principal, as a rejected token would.
	router := newTestRouter(Handler{Service: &fakeService{}}, 0)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/user/identities/github?code=c", nil))

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
}

func TestBindMapsConflictCodes(t *testing.T) {
	tests := []struct {
		name       string
		code       int
		wantStatus int
	}{
		{"occupied by another user", errcode.CodeIdentityOccupied, http.StatusConflict},
		{"already bound to caller", errcode.CodeIdentityAlreadyBound, http.StatusConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeService{bindErr: &oauthlogin.Error{
				Kind: oauthlogin.KindConflict,
				Code: test.code,
			}}
			router := newTestRouter(Handler{Service: service}, 42)

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodPost,
				"/user/identities/github?code=c", nil))

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
			code, _, _ := decodeEnvelope(t, recorder.Body.String())
			if code != test.code {
				t.Fatalf("code = %d, want %d", code, test.code)
			}
		})
	}
}

func TestProviderOutageMapsTo502(t *testing.T) {
	service := &fakeService{bindErr: &oauthlogin.Error{
		Kind: oauthlogin.KindProviderUnavailable,
		Code: errcode.CodeDependencyUnavailable,
	}}
	router := newTestRouter(Handler{Service: service}, 42)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/user/identities/github?code=c", nil))

	// 502, not 503: this service is healthy; GitHub answered badly.
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", recorder.Code)
	}
}

func TestRedisOutageMapsTo503(t *testing.T) {
	service := &fakeService{exchangeErr: &oauthlogin.Error{
		Kind: oauthlogin.KindDependencyUnavailable,
		Code: errcode.CodeDependencyUnavailable,
	}}
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/exchange-code",
		strings.NewReader(`{"code":"lc_abc"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
}
