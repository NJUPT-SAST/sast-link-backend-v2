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
	RegisterRoutes(router, h, Gates{
		RequireAuth:       authMiddleware,
		RequireWriteScope: func(c *gin.Context) { c.Next() },
	})
	return router
}

// bindRequest builds a POST to a binding endpoint carrying the step-up password.
func bindRequest(target string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target,
		strings.NewReader(`{"password":"secret"}`))
	req.Header.Set("Content-Type", "application/json")
	return req
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
		OAuthState:        "os_abc",
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
	// POST /auth/register requires both halves of the double binding, and the
	// page that began the login was unloaded by the redirect to the provider.
	// Without this the registration branch cannot complete at all.
	if query.Get("oauth_state") != "os_abc" {
		t.Fatalf("oauth_state = %q, want os_abc", query.Get("oauth_state"))
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

// The user declining on the provider's page must land on the frontend callback
// page with error=access_denied — that page renders its own "已取消登录" state
// instead of treating the decline as a failure on the error page.
func TestCallbackCancellationRedirectsToFrontendCallbackPage(t *testing.T) {
	service := &fakeService{callbackResult: &oauthlogin.CallbackResult{
		Cancelled: true,
		Provider:  "github",
		Redirect:  "https://link.sast.fun/oauth/callback",
	}}
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/oauth/github/callback?error=access_denied&state=s", nil))

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 to the frontend callback page", recorder.Code)
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if location.Query().Get("error") != "access_denied" {
		t.Fatalf("error = %q, want access_denied", location.Query().Get("error"))
	}
	if location.Query().Get("provider") != "github" {
		t.Fatalf("provider = %q, want github", location.Query().Get("provider"))
	}
	if !strings.HasPrefix(location.String(), "https://link.sast.fun/oauth/callback") {
		t.Fatalf("Location = %q, want the frontend callback page", location)
	}
	// The provider error string is forwarded to the service so it can tell a
	// cancellation apart from a parameter failure.
	if service.callbackInput.ProviderError != "access_denied" {
		t.Fatalf("ProviderError = %q, want access_denied", service.callbackInput.ProviderError)
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

// A refused authorization code and an expired state share KindInvalidState and
// code 40000, so the generic per-Kind string cannot describe both. The service
// marks the specific one for display, and it must reach the error page intact:
// this is exactly the case that read as "state 无效或已过期" while the state was
// valid.
func TestCallbackFailureCarriesTheDisplayMessageOverTheKindDefault(t *testing.T) {
	service := &fakeService{callbackErr: &oauthlogin.Error{
		Kind:    oauthlogin.KindInvalidState,
		Code:    errcode.CodeBadRequest,
		Message: "第三方授权码无效或已过期",
		Display: true,
	}}
	router := newTestRouter(Handler{
		Service:       service,
		ErrorRedirect: "https://link.sast.fun/oauth/error",
	}, 0)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/oauth/github/callback?code=c&state=s", nil))

	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := location.Query().Get("error_description"); got != "第三方授权码无效或已过期" {
		t.Fatalf("error_description = %q, want the service's own message", got)
	}
}

// The inverse: a message naming an internal step is not marked for display and
// must be replaced by the generic string, so a dependency name never reaches a
// browser.
func TestCallbackFailureHidesInternalMessages(t *testing.T) {
	service := &fakeService{callbackErr: &oauthlogin.Error{
		Kind:    oauthlogin.KindDependencyUnavailable,
		Code:    errcode.CodeDependencyUnavailable,
		Message: "读取 OAuth state 失败",
	}}
	router := newTestRouter(Handler{
		Service:       service,
		ErrorRedirect: "https://link.sast.fun/oauth/error",
	}, 0)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/oauth/github/callback?code=c&state=s", nil))

	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := location.Query().Get("error_description"); got != "依赖服务暂不可用" {
		t.Fatalf("error_description = %q, want the generic per-Kind string", got)
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

func TestExchangeCodeSetsSessionCookie(t *testing.T) {
	service := &fakeService{exchangeResult: &oauthlogin.ExchangeCodeResult{
		AccessToken:      "access",
		RefreshToken:     "refresh",
		TokenType:        "Bearer",
		AccessExpiresAt:  time.Now().Add(time.Hour),
		RefreshExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		User: &model.User{
			ID: 42, Name: "Existing", LoginEmail: "existing@sast.fun",
			Role: model.UserRoleFreshman, State: model.UserStateNJUPTer,
		},
	}}
	cookies := &middleware.SessionCookie{Name: "sl_session", Path: "/v2", SameSite: http.SameSiteLaxMode}
	router := newTestRouter(Handler{Service: service, Cookies: cookies}, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/exchange-code",
		strings.NewReader(`{"code":"lc_abc"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", recorder.Code, recorder.Body.String())
	}
	setCookie := recorder.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "sl_session=refresh") || !strings.Contains(setCookie, "HttpOnly") {
		t.Fatalf("Set-Cookie = %q, want session cookie with refresh token", setCookie)
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
	router.ServeHTTP(recorder, bindRequest("/user/identities/github?code=provider-code&redirect_uri=https%3A%2F%2Flink.sast.fun%2Foauth%2Fbind%2Fgithub"))

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
	if service.bindInput.Password != "secret" {
		t.Fatalf("password = %q, want the body value", service.bindInput.Password)
	}
	// The frontend bind callback must be echoed back so the provider code can be
	// exchanged against the exact callback it was issued for (RFC 6749 §4.1.3).
	if service.bindInput.RedirectURI != "https://link.sast.fun/oauth/bind/github" {
		t.Fatalf("redirect_uri = %q, want the query value", service.bindInput.RedirectURI)
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
	router.ServeHTTP(recorder, bindRequest("/user/identities/lark?code=provider-code"))

	_, _, data := decodeEnvelope(t, recorder.Body.String())
	if data["message"] != "飞书账号绑定成功" {
		t.Fatalf("message = %v", data["message"])
	}
}

func TestBindWithoutPrincipalIs401(t *testing.T) {
	// userID 0 makes the middleware set no principal, as a rejected token would.
	router := newTestRouter(Handler{Service: &fakeService{}}, 0)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, bindRequest("/user/identities/github?code=c"))

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
			router.ServeHTTP(recorder, bindRequest("/user/identities/github?code=c"))

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
	router.ServeHTTP(recorder, bindRequest("/user/identities/github?code=c"))

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

// A throttled service error must surface as 429 with Retry-After, so clients can
// back off instead of hammering a capped endpoint.
func TestExchangeCodeMapsRateLimitTo429(t *testing.T) {
	service := &fakeService{exchangeErr: &oauthlogin.Error{
		Kind:       oauthlogin.KindRateLimited,
		Code:       errcode.CodeRateLimited,
		RetryAfter: 30 * time.Second,
	}}
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/exchange-code",
		strings.NewReader(`{"code":"lc_abc"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (body: %s)", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Retry-After"); got != "30" {
		t.Fatalf("Retry-After = %q, want %q", got, "30")
	}
	code, _, _ := decodeEnvelope(t, recorder.Body.String())
	if code != errcode.CodeRateLimited {
		t.Fatalf("envelope code = %d, want %d", code, errcode.CodeRateLimited)
	}
}

// The authorize leg answers in the envelope even though it arrives in a browser:
// unlike the callback it is the entry point, so there is no in-flight login whose
// state would be lost by not redirecting.
func TestAuthorizeMapsRateLimitTo429(t *testing.T) {
	service := &fakeService{authorizeErr: &oauthlogin.Error{
		Kind: oauthlogin.KindRateLimited,
		Code: errcode.CodeRateLimited,
	}}
	router := newTestRouter(Handler{Service: service, ErrorRedirect: "https://link.sast.fun/error"}, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/github", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (body: %s)", recorder.Code, recorder.Body.String())
	}
}

// The authorize leg writes the login-CSRF state cookie, so the callback can
// prove it completes in the browser that started the authorization.
func TestAuthorizeSetsStateCookie(t *testing.T) {
	service := &fakeService{authorizeResult: &oauthlogin.AuthorizeResult{
		AuthorizeURL: "https://github.test/authorize?state=os_abc",
		State:        "os_abc",
		StateDigest:  "deadbeef",
		StateTTL:     10 * time.Minute,
	}}
	stateCookie := &middleware.SessionCookie{
		Name: "sl_oauth_state", Path: "/v2", Secure: true, SameSite: http.SameSiteLaxMode,
	}
	router := newTestRouter(Handler{Service: service, StateCookie: stateCookie}, 0)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/github", nil))

	response := recorder.Result()
	defer response.Body.Close()
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie count = %d, want the state cookie", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != "sl_oauth_state" || cookie.Value != "deadbeef" {
		t.Fatalf("state cookie = %q=%q, want sl_oauth_state=deadbeef", cookie.Name, cookie.Value)
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || !cookie.Secure {
		t.Fatalf("state cookie attributes = %+v, want HttpOnly, SameSite=Lax, Secure", cookie)
	}
	if cookie.MaxAge != 600 {
		t.Fatalf("state cookie Max-Age = %d, want the state TTL in seconds", cookie.MaxAge)
	}
}

// The callback presents the cookie back to the service and clears it — the
// state is consumed either way, so the pairing is spent.
func TestCallbackPassesStateCookieAndClearsIt(t *testing.T) {
	service := &fakeService{callbackResult: &oauthlogin.CallbackResult{
		Bound:     true,
		LoginCode: "lc_abc123",
		Redirect:  "https://link.sast.fun/callback",
	}}
	stateCookie := &middleware.SessionCookie{
		Name: "sl_oauth_state", Path: "/v2", Secure: true, SameSite: http.SameSiteLaxMode,
	}
	router := newTestRouter(Handler{Service: service, StateCookie: stateCookie}, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/oauth/github/callback?code=provider-code&state=os_abc", nil)
	// #nosec G124 -- test fixture: a browser callback request, not a cookie this
	// service writes.
	request.AddCookie(&http.Cookie{Name: "sl_oauth_state", Value: "deadbeef"})
	router.ServeHTTP(recorder, request)

	if service.callbackInput.StateCookie != "deadbeef" {
		t.Fatalf("callback StateCookie = %q, want the cookie value", service.callbackInput.StateCookie)
	}
	response := recorder.Result()
	defer response.Body.Close()
	for _, cookie := range response.Cookies() {
		if cookie.Name == "sl_oauth_state" && cookie.MaxAge >= 0 {
			t.Fatalf("state cookie was not cleared: Max-Age = %d", cookie.MaxAge)
		}
	}
}

// Without the state cookie wired, the handler passes an empty cookie value —
// the service refuses the callback rather than silently dropping the defense.
func TestCallbackWithoutStateCookieWirePassesEmptyValue(t *testing.T) {
	service := &fakeService{callbackResult: &oauthlogin.CallbackResult{
		Bound:     true,
		LoginCode: "lc_abc123",
		Redirect:  "https://link.sast.fun/callback",
	}}
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/oauth/github/callback?code=provider-code&state=os_abc", nil))

	if service.callbackInput.StateCookie != "" {
		t.Fatalf("callback StateCookie = %q, want empty when the cookie is not wired", service.callbackInput.StateCookie)
	}
}
