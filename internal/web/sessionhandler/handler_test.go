package sessionhandler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }

type fakeService struct {
	loginResult   *session.LoginResult
	refreshResult *session.RefreshResult
	logoutResult  *session.LogoutResult
	profileResult *session.ProfileResult
	loginErr      error
	refreshErr    error
	logoutErr     error
	profileErr    error
	loginInput    session.LoginInput
	refreshInput  session.RefreshInput
	logoutInput   session.LogoutInput
	profileInput  session.ProfileInput
	loginCalls    int
	refreshCalls  int
	logoutCalls   int
}

func (s *fakeService) Login(_ context.Context, input session.LoginInput) (*session.LoginResult, error) {
	s.loginCalls++
	s.loginInput = input
	return s.loginResult, s.loginErr
}

func (s *fakeService) Refresh(_ context.Context, input session.RefreshInput) (*session.RefreshResult, error) {
	s.refreshCalls++
	s.refreshInput = input
	return s.refreshResult, s.refreshErr
}

func (s *fakeService) Logout(_ context.Context, input session.LogoutInput) (*session.LogoutResult, error) {
	s.logoutCalls++
	s.logoutInput = input
	return s.logoutResult, s.logoutErr
}

func (s *fakeService) Profile(_ context.Context, input session.ProfileInput) (*session.ProfileResult, error) {
	s.profileInput = input
	return s.profileResult, s.profileErr
}

func TestLoginReturnsEnvelopeDTOAndInput(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	service := &fakeService{loginResult: &session.LoginResult{
		AccessToken:     "access",
		RefreshToken:    "refresh",
		TokenType:       "Bearer",
		Scope:           "openid profile email",
		AccessExpiresAt: now.Add(90 * time.Second),
		Profile: session.UserProfileDTO{
			ID:         42,
			Name:       "pt",
			LoginEmail: "pt@sast.fun",
			Role:       "member",
			State:      "on_sast",
		},
	}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service, Clock: fixedClock{value: now}}, allowAuth())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/user/login", strings.NewReader(`{"login_email":"pt@sast.fun","password":"secret"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "agent")
	router.ServeHTTP(recorder, request)

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 || body.Message != "ok" {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	data := body.Data.(map[string]any)
	if data["access_token"] != "access" || data["refresh_token"] != "refresh" || data["expires_in"] != float64(90) {
		t.Fatalf("data = %#v", data)
	}
	if _, exists := data["scope"]; exists {
		t.Fatalf("login response leaked scope: %#v", data)
	}
	user := data["user"].(map[string]any)
	if user["login_email"] != "pt@sast.fun" || user["id"] != float64(42) {
		t.Fatalf("user = %#v", user)
	}
	if _, exists := data["profile"]; exists {
		t.Fatalf("login response used profile instead of user: %#v", data)
	}
	if service.loginInput.Identifier != "pt@sast.fun" || service.loginInput.Password != "secret" || service.loginInput.UserAgent != "agent" {
		t.Fatalf("login input = %+v", service.loginInput)
	}
}

func TestRefreshReturnsTokenEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	service := &fakeService{refreshResult: &session.RefreshResult{
		AccessToken:     "new-access",
		RefreshToken:    "new-refresh",
		TokenType:       "Bearer",
		Scope:           "openid",
		AccessExpiresAt: now.Add(time.Minute),
	}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service, Clock: fixedClock{value: now}}, allowAuth())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/refresh", strings.NewReader(`{"refresh_token":"rt_x"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	body := decodeBody(t, recorder)
	data := body.Data.(map[string]any)
	if recorder.Code != http.StatusOK || data["access_token"] != "new-access" || data["expires_in"] != float64(60) {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	if _, exists := data["scope"]; exists {
		t.Fatalf("refresh response leaked scope: %#v", data)
	}
}

func TestProtectedLogoutUsesPrincipalOnlyFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	expires := time.Date(2026, 7, 22, 11, 0, 0, 0, time.UTC)
	service := &fakeService{logoutResult: &session.LogoutResult{BlacklistedJTI: "jti", FamilyID: "family"}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, allowAuthWith(middleware.Principal{UserID: 42, JTI: "jti", ExpiresAt: expires}))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/logout", strings.NewReader(`{"refresh_token":"rt_x"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	body := decodeBody(t, recorder)
	data := body.Data.(map[string]any)
	if recorder.Code != http.StatusOK || data["message"] != "已登出" {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	if _, exists := data["blacklisted_jti"]; exists {
		t.Fatalf("logout response leaked jti: %#v", data)
	}
	if _, exists := data["family_id"]; exists {
		t.Fatalf("logout response leaked family: %#v", data)
	}
	if service.logoutInput.PrincipalJTI != "jti" || service.logoutInput.PrincipalUserID != 42 || service.logoutInput.RefreshToken != "rt_x" {
		t.Fatalf("logout input = %+v", service.logoutInput)
	}
}

func TestProtectedProfileUsesPrincipalUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{profileResult: &session.ProfileResult{Profile: session.UserProfileDTO{ID: 42, Name: "pt"}}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, allowAuthWith(middleware.Principal{UserID: 42, JTI: "jti", ExpiresAt: time.Now()}))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/user/profile", nil))
	body := decodeBody(t, recorder)
	data := body.Data.(map[string]any)
	if recorder.Code != http.StatusOK || service.profileInput.UserID != 42 || data["id"] != float64(42) || data["name"] != "pt" {
		t.Fatalf("response = %d %#v input=%+v", recorder.Code, body, service.profileInput)
	}
}

func TestServiceErrorMappingDoesNotLeakCause(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{loginErr: &session.Error{Kind: session.KindInternal, Code: errcode.CodeInternal, Message: "db password leaked", Err: errors.New("secret DSN")}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, allowAuth())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/user/login", strings.NewReader(`{"login_email":"pt@sast.fun","password":"secret"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusInternalServerError || body.Code != errcode.CodeInternal || body.Message != "服务器内部错误" || strings.Contains(recorder.Body.String(), "secret DSN") || strings.Contains(recorder.Body.String(), "db password leaked") {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
}

func TestServiceErrorMappingStatusAndCode(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   int
	}{
		{name: "invalid input", err: &session.Error{Kind: session.KindInvalidInput, Code: errcode.CodeBadRequest, Message: "bad"}, wantStatus: http.StatusBadRequest, wantCode: errcode.CodeBadRequest},
		{name: "unknown identifier", err: &session.Error{Kind: session.KindUnknownIdentifier, Code: errcode.CodeUnknownIdentifier, Message: "unknown"}, wantStatus: http.StatusUnauthorized, wantCode: errcode.CodeUnknownIdentifier},
		{name: "bad password", err: &session.Error{Kind: session.KindPasswordInvalid, Code: errcode.CodePasswordInvalid, Message: "bad password"}, wantStatus: http.StatusUnauthorized, wantCode: errcode.CodePasswordInvalid},
		{name: "deleted", err: &session.Error{Kind: session.KindUserDeleted, Code: errcode.CodeAccountDeleted, Message: "deleted"}, wantStatus: http.StatusForbidden, wantCode: errcode.CodeAccountDeleted},
		{name: "rate", err: &session.Error{Kind: session.KindRateLimited, Code: errcode.CodeRateLimited, Message: "rate"}, wantStatus: http.StatusTooManyRequests, wantCode: errcode.CodeRateLimited},
		{name: "rate with retry", err: &session.Error{Kind: session.KindRateLimited, Code: errcode.CodeRateLimited, Message: "rate", RetryAfter: time.Minute}, wantStatus: http.StatusTooManyRequests, wantCode: errcode.CodeRateLimited},
		{name: "invalid token", err: &session.Error{Kind: session.KindInvalidToken, Code: errcode.CodeAccessTokenInvalid, Message: "invalid token"}, wantStatus: http.StatusUnauthorized, wantCode: errcode.CodeAccessTokenInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapped := mapServiceError(test.err).(*response.BusinessError)
			if mapped.HTTPStatus != test.wantStatus || mapped.Code != test.wantCode || mapped.Message == "" {
				t.Fatalf("mapped = %+v", mapped)
			}
			if strings.Contains(mapped.Message, test.err.Error()) {
				t.Fatalf("mapped message leaked service error: %+v", mapped)
			}
			if se, ok := test.err.(*session.Error); ok && se.RetryAfter > 0 && mapped.RetryAfter != se.RetryAfter {
				t.Fatalf("RetryAfter = %v, want %v", mapped.RetryAfter, se.RetryAfter)
			}
		})
	}
}

func TestInvalidJSONRequestsReturnBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	RegisterRoutes(router, Handler{Service: &fakeService{}}, allowAuth())
	for _, route := range []string{"/user/login", "/auth/refresh", "/auth/logout"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, route, strings.NewReader(`{}`))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, request)
		body := decodeBody(t, recorder)
		if recorder.Code != http.StatusBadRequest || body.Code != errcode.CodeBadRequest {
			t.Fatalf("%s response = %d %#v", route, recorder.Code, body)
		}
	}
}

func TestProtectedRoutesRequireMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	RegisterRoutes(router, Handler{Service: &fakeService{}}, func(c *gin.Context) {
		response.Error(c, &response.BusinessError{HTTPStatus: http.StatusUnauthorized, Code: errcode.CodeUnauthenticated, Message: "missing or invalid authorization header"})
		c.Abort()
	})
	for _, test := range []struct{ method, path string }{{http.MethodPost, "/auth/logout"}, {http.MethodGet, "/user/profile"}} {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), test.method, test.path, strings.NewReader(`{"refresh_token":"rt_x"}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, req)
		body := decodeBody(t, recorder)
		if recorder.Code != http.StatusUnauthorized || body.Code != errcode.CodeUnauthenticated {
			t.Fatalf("%s response = %d %#v", test.path, recorder.Code, body)
		}
	}
}

func TestLoginClientIPDoesNotTrustXForwardedFor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{loginResult: &session.LoginResult{AccessToken: "a", RefreshToken: "r", TokenType: "Bearer", AccessExpiresAt: time.Now().Add(time.Hour)}}
	router, err := web.NewRouter(nil, []string{"127.0.0.1", "::1"}, 31536000)
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}
	RegisterRoutes(router, Handler{Service: service}, allowAuth())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/user/login", strings.NewReader(`{"login_email":"pt@sast.fun","password":"secret"}`))
	request.RemoteAddr = "203.0.113.9:12345"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-For", "198.51.100.7")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.loginInput.ClientIP != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want RemoteAddr host not XFF", service.loginInput.ClientIP)
	}
}

func TestSessionRequestsUseStrictBoundedJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name      string
		path      string
		body      string
		wantCalls func(*fakeService) int
	}{
		{name: "login rejects unknown field", path: "/user/login", body: `{"login_email":"pt@sast.fun","password":"secret","unknown":true}`, wantCalls: func(s *fakeService) int { return s.loginCalls }},
		{name: "refresh rejects trailing value", path: "/auth/refresh", body: `{"refresh_token":"rt_x"} {}`, wantCalls: func(s *fakeService) int { return s.refreshCalls }},
		{name: "logout rejects empty body", path: "/auth/logout", body: ``, wantCalls: func(s *fakeService) int { return s.logoutCalls }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeService{}
			router := gin.New()
			RegisterRoutes(router, Handler{Service: service}, allowAuth())
			request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			body := decodeBody(t, recorder)
			if recorder.Code != http.StatusBadRequest || body.Code != errcode.CodeBadRequest || test.wantCalls(service) != 0 {
				t.Fatalf("response=%d %#v service calls=%d", recorder.Code, body, test.wantCalls(service))
			}
		})
	}
}

func TestSessionRequestsRejectNonJSONContentType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded"} {
		t.Run(contentType, func(t *testing.T) {
			service := &fakeService{}
			router := gin.New()
			RegisterRoutes(router, Handler{Service: service}, allowAuth())
			request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/user/login", strings.NewReader(`{"login_email":"pt@sast.fun","password":"secret"}`))
			if contentType != "" {
				request.Header.Set("Content-Type", contentType)
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			body := decodeBody(t, recorder)
			if recorder.Code != http.StatusBadRequest || body.Code != errcode.CodeBadRequest || service.loginCalls != 0 {
				t.Fatalf("response=%d %#v service calls=%d", recorder.Code, body, service.loginCalls)
			}
		})
	}
}

func TestSessionRequestsAcceptJSONCharset(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	service := &fakeService{loginResult: &session.LoginResult{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", AccessExpiresAt: now.Add(time.Minute)}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service, Clock: fixedClock{value: now}}, allowAuth())
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/user/login", strings.NewReader(`{"login_email":"pt@sast.fun","password":"secret"}`))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || service.loginCalls != 1 {
		t.Fatalf("response=%d body=%s service calls=%d", recorder.Code, recorder.Body.String(), service.loginCalls)
	}
}

func TestSessionRequestsRejectOversizedJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, allowAuth())
	body := `{"login_email":"pt@sast.fun","password":"` + strings.Repeat("a", int(maxJSONRequestBodyBytes)) + `"}`
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/user/login", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	responseBody := decodeBody(t, recorder)
	if recorder.Code != http.StatusBadRequest || responseBody.Code != errcode.CodeBadRequest || service.loginCalls != 0 {
		t.Fatalf("response=%d %#v service calls=%d", recorder.Code, responseBody, service.loginCalls)
	}
}

func allowAuth() gin.HandlerFunc {
	return allowAuthWith(middleware.Principal{UserID: 1, JTI: "jti", ExpiresAt: time.Now().Add(time.Hour)})
}

func allowAuthWith(principal middleware.Principal) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("principal", principal)
		c.Next()
	}
}

type responseBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

func decodeBody(t *testing.T, recorder *httptest.ResponseRecorder) responseBody {
	t.Helper()
	var body responseBody
	decoder := json.NewDecoder(recorder.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, recorder.Body.String())
	}
	body.Data = normalizeJSON(body.Data)
	return body
}

func normalizeJSON(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			typed[key] = normalizeJSON(child)
		}
		return typed
	case []any:
		for index, child := range typed {
			typed[index] = normalizeJSON(child)
		}
		return typed
	case json.Number:
		floatValue, _ := typed.Float64()
		return floatValue
	default:
		return typed
	}
}
