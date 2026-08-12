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
	loginResult              *session.LoginResult
	refreshResult            *session.RefreshResult
	logoutResult             *session.LogoutResult
	profileResult            *session.ProfileResult
	sendRegisterCodeResult   *session.SendRegisterCodeResult
	verifyRegisterCodeResult *session.VerifyRegisterCodeResult
	registerResult           *session.RegisterResult
	forgotPasswordResult     *session.ForgotPasswordResult
	resetPasswordResult      *session.ResetPasswordResult
	changePasswordResult     *session.ChangePasswordResult
	bindEmailSendCodeResult  *session.BindEmailSendCodeResult
	bindEmailVerifyResult    *session.BindEmailVerifyResult
	updateProfileResult      *session.UpdateProfileResult
	uploadAvatarResult       *session.UploadAvatarResult
	listIdentitiesResult     *session.ListIdentitiesResult
	unbindIdentityResult     *session.UnbindIdentityResult
	cardResult               *session.CardResult
	listDevicesResult        *session.ListDevicesResult
	logoutDeviceResult       *session.LogoutDeviceResult
	loginErr                 error
	refreshErr               error
	logoutErr                error
	profileErr               error
	sendRegisterCodeErr      error
	verifyRegisterCodeErr    error
	registerErr              error
	forgotPasswordErr        error
	resetPasswordErr         error
	changePasswordErr        error
	bindEmailSendCodeErr     error
	bindEmailVerifyErr       error
	updateProfileErr         error
	uploadAvatarErr          error
	listIdentitiesErr        error
	unbindIdentityErr        error
	cardErr                  error
	listDevicesErr           error
	logoutDeviceErr          error
	loginInput               session.LoginInput
	refreshInput             session.RefreshInput
	logoutInput              session.LogoutInput
	profileInput             session.ProfileInput
	sendRegisterCodeInput    session.SendRegisterCodeInput
	verifyRegisterCodeInput  session.VerifyRegisterCodeInput
	registerInput            session.RegisterInput
	forgotPasswordInput      session.ForgotPasswordInput
	resetPasswordInput       session.ResetPasswordInput
	changePasswordInput      session.ChangePasswordInput
	bindEmailSendCodeInput   session.BindEmailSendCodeInput
	bindEmailVerifyInput     session.BindEmailVerifyInput
	updateProfileInput       session.UpdateProfileInput
	uploadAvatarInput        session.UploadAvatarInput
	listIdentitiesInput      session.ListIdentitiesInput
	unbindIdentityInput      session.UnbindIdentityInput
	cardInput                session.CardInput
	listDevicesInput         session.ListDevicesInput
	logoutDeviceInput        session.LogoutDeviceInput
	updateProfileCalls       int
	uploadAvatarCalls        int
	unbindIdentityCalls      int
	cardCalls                int
	listDevicesCalls         int
	logoutDeviceCalls        int
	loginCalls               int
	refreshCalls             int
	logoutCalls              int
	sendRegisterCodeCalls    int
	verifyRegisterCodeCalls  int
	registerCalls            int
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

func (s *fakeService) SendRegisterCode(_ context.Context, input session.SendRegisterCodeInput) (*session.SendRegisterCodeResult, error) {
	s.sendRegisterCodeCalls++
	s.sendRegisterCodeInput = input
	return s.sendRegisterCodeResult, s.sendRegisterCodeErr
}

func (s *fakeService) VerifyRegisterCode(_ context.Context, input session.VerifyRegisterCodeInput) (*session.VerifyRegisterCodeResult, error) {
	s.verifyRegisterCodeCalls++
	s.verifyRegisterCodeInput = input
	return s.verifyRegisterCodeResult, s.verifyRegisterCodeErr
}

func (s *fakeService) Register(_ context.Context, input session.RegisterInput) (*session.RegisterResult, error) {
	s.registerCalls++
	s.registerInput = input
	return s.registerResult, s.registerErr
}

func (s *fakeService) ForgotPasswordSendCode(_ context.Context, input session.ForgotPasswordInput) (*session.ForgotPasswordResult, error) {
	s.forgotPasswordInput = input
	return s.forgotPasswordResult, s.forgotPasswordErr
}

func (s *fakeService) ResetPassword(_ context.Context, input session.ResetPasswordInput) (*session.ResetPasswordResult, error) {
	s.resetPasswordInput = input
	return s.resetPasswordResult, s.resetPasswordErr
}

func (s *fakeService) ChangePassword(_ context.Context, input session.ChangePasswordInput) (*session.ChangePasswordResult, error) {
	s.changePasswordInput = input
	return s.changePasswordResult, s.changePasswordErr
}

func (s *fakeService) BindEmailSendCode(_ context.Context, input session.BindEmailSendCodeInput) (*session.BindEmailSendCodeResult, error) {
	s.bindEmailSendCodeInput = input
	return s.bindEmailSendCodeResult, s.bindEmailSendCodeErr
}

func (s *fakeService) BindEmailVerify(_ context.Context, input session.BindEmailVerifyInput) (*session.BindEmailVerifyResult, error) {
	s.bindEmailVerifyInput = input
	return s.bindEmailVerifyResult, s.bindEmailVerifyErr
}

func (s *fakeService) UpdateProfile(_ context.Context, input session.UpdateProfileInput) (*session.UpdateProfileResult, error) {
	s.updateProfileCalls++
	s.updateProfileInput = input
	return s.updateProfileResult, s.updateProfileErr
}

func (s *fakeService) UploadAvatar(_ context.Context, input session.UploadAvatarInput) (*session.UploadAvatarResult, error) {
	s.uploadAvatarCalls++
	s.uploadAvatarInput = input
	return s.uploadAvatarResult, s.uploadAvatarErr
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
	RegisterRoutes(router, Handler{Service: service, Clock: fixedClock{value: now}}, scopedGates(allowAuth()))
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
	RegisterRoutes(router, Handler{Service: service, Clock: fixedClock{value: now}}, scopedGates(allowAuth()))
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
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuthWith(middleware.Principal{UserID: 42, JTI: "jti", ExpiresAt: expires})))
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
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuthWith(middleware.Principal{UserID: 42, JTI: "jti", ExpiresAt: time.Now()})))
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
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuth()))
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
		{name: "dependency unavailable", err: &session.Error{Kind: session.KindDependencyUnavailable, Code: errcode.CodeDependencyUnavailable, Message: "redis down"}, wantStatus: http.StatusServiceUnavailable, wantCode: errcode.CodeDependencyUnavailable},
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
	RegisterRoutes(router, Handler{Service: &fakeService{}}, scopedGates(allowAuth()))
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
	RegisterRoutes(router, Handler{Service: &fakeService{}}, scopedGates(func(c *gin.Context) {
		response.Error(c, &response.BusinessError{HTTPStatus: http.StatusUnauthorized, Code: errcode.CodeUnauthenticated, Message: "missing or invalid authorization header"})
		c.Abort()
	}))
	for _, test := range []struct{ method, path string }{
		{http.MethodPost, "/auth/logout"},
		{http.MethodGet, "/user/profile"},
		{http.MethodPut, "/user/profile"},
		{http.MethodPost, "/auth/change-password"},
		{http.MethodGet, "/user/identities"},
		{http.MethodPost, "/user/identities/email"},
		{http.MethodPost, "/user/identities/email/verify"},
		{http.MethodDelete, "/user/identities/12"},
	} {
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
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuth()))
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

func TestSendRegisterCodeReturnsMessageAndExpiry(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{sendRegisterCodeResult: &session.SendRegisterCodeResult{Email: "pt@sast.fun", ExpiresIn: 300}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuth()))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/register/send-code", strings.NewReader(`{"login_email":"pt@sast.fun"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	data := body.Data.(map[string]any)
	if data["message"] != "验证码已发送至邮箱" || data["expires_in"] != float64(300) {
		t.Fatalf("data = %#v", data)
	}
	if service.sendRegisterCodeInput.Email != "pt@sast.fun" || service.sendRegisterCodeInput.UserAgent != "" {
		t.Fatalf("send code input = %+v", service.sendRegisterCodeInput)
	}
}

func TestSendRegisterCodeMapsDomainError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{sendRegisterCodeErr: &session.Error{Kind: session.KindInvalidInput, Code: errcode.CodeEmailDomainNotAllowed, Message: "邮箱域名不允许"}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuth()))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/register/send-code", strings.NewReader(`{"login_email":"pt@gmail.com"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusBadRequest || body.Code != errcode.CodeEmailDomainNotAllowed {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
}

func TestVerifyRegisterCodeReturnsTicket(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{verifyRegisterCodeResult: &session.VerifyRegisterCodeResult{RegisterTicket: "reg_xxx", Email: "pt@sast.fun", ExpiresIn: 300}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuth()))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/register/verify-code", strings.NewReader(`{"login_email":"pt@sast.fun","code":"123456"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	data := body.Data.(map[string]any)
	if data["register_ticket"] != "reg_xxx" || data["expires_in"] != float64(300) {
		t.Fatalf("data = %#v", data)
	}
}

func TestRegisterReturnsTokensAndUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	service := &fakeService{registerResult: &session.RegisterResult{
		AccessToken:     "access",
		RefreshToken:    "refresh",
		TokenType:       "Bearer",
		Scope:           "openid profile email",
		AccessExpiresAt: now.Add(90 * time.Second),
		Profile: session.UserProfileDTO{
			ID:         7,
			Name:       "pt",
			LoginEmail: "pt@sast.fun",
			Role:       "freshman",
			State:      "njupter",
		},
	}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service, Clock: fixedClock{value: now}}, scopedGates(allowAuth()))
	recorder := httptest.NewRecorder()
	body := `{"register_ticket":"reg_xxx","password":"password123","name":"pt","student_id":"B24040001","phone_number":"13800138000","qq_number":"10000","college":"其他","major":"CS"}`
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/register", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	resp := decodeBody(t, recorder)
	if recorder.Code != http.StatusCreated || resp.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, resp)
	}
	data := resp.Data.(map[string]any)
	if data["access_token"] != "access" || data["refresh_token"] != "refresh" {
		t.Fatalf("data = %#v", data)
	}
	if service.registerInput.Password != "password123" || service.registerInput.Name != "pt" || service.registerInput.College != "其他" {
		t.Fatalf("register input = %+v", service.registerInput)
	}
}

func TestChangePasswordReturnsMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{changePasswordResult: &session.ChangePasswordResult{UserID: 42}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuthWith(middleware.Principal{UserID: 42, JTI: "jti", ExpiresAt: time.Now().Add(time.Hour)})))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/change-password", strings.NewReader(`{"old_password":"oldpassword","new_password":"newpassword"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	data := body.Data.(map[string]any)
	if data["message"] != "密码修改成功" {
		t.Fatalf("data = %#v", data)
	}
	if service.changePasswordInput.UserID != 42 || service.changePasswordInput.OldPassword != "oldpassword" || service.changePasswordInput.NewPassword != "newpassword" {
		t.Fatalf("change password input = %+v", service.changePasswordInput)
	}
}

func TestResetPasswordReturnsMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{resetPasswordResult: &session.ResetPasswordResult{Email: "pt@sast.fun"}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuth()))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/reset-password", strings.NewReader(`{"login_email":"pt@sast.fun","code":"123456","new_password":"newpassword"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	data := body.Data.(map[string]any)
	if data["message"] != "密码重置成功，请重新登录" {
		t.Fatalf("data = %#v", data)
	}
	if service.resetPasswordInput.Email != "pt@sast.fun" || service.resetPasswordInput.Password != "newpassword" {
		t.Fatalf("reset password input = %+v", service.resetPasswordInput)
	}
}

func TestBindEmailSendCodeReturnsTicketAndExpiry(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{bindEmailSendCodeResult: &session.BindEmailSendCodeResult{BindTicket: "be_ticket", ExpiresIn: 300}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuthWith(middleware.Principal{UserID: 42, JTI: "jti", ExpiresAt: time.Now().Add(time.Hour)})))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/user/identities/email", strings.NewReader(`{"email":"extra@qq.com"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	data := body.Data.(map[string]any)
	if data["bind_ticket"] != "be_ticket" || data["expires_in"] != float64(300) {
		t.Fatalf("data = %#v", data)
	}
	if service.bindEmailSendCodeInput.UserID != 42 || service.bindEmailSendCodeInput.Email != "extra@qq.com" {
		t.Fatalf("bind email input = %+v", service.bindEmailSendCodeInput)
	}
}

func TestBindEmailVerifyReturnsIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{bindEmailVerifyResult: &session.BindEmailVerifyResult{
		Email: "extra@qq.com",
		Identity: session.IdentityDTO{
			ID:         7,
			Provider:   "other_mail",
			ProviderID: "extra@qq.com",
		},
	}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuthWith(middleware.Principal{UserID: 42, JTI: "jti", ExpiresAt: time.Now().Add(time.Hour)})))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/user/identities/email/verify", strings.NewReader(`{"bind_ticket":"be_ticket","code":"123456"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	data := body.Data.(map[string]any)
	if data["message"] != "邮箱绑定成功" {
		t.Fatalf("data = %#v", data)
	}
	identity, ok := data["identity"].(map[string]any)
	if !ok || identity["provider"] != "other_mail" || identity["provider_id"] != "extra@qq.com" {
		t.Fatalf("identity = %#v", data["identity"])
	}
	if service.bindEmailVerifyInput.UserID != 42 || service.bindEmailVerifyInput.BindTicket != "be_ticket" || service.bindEmailVerifyInput.Code != "123456" {
		t.Fatalf("bind verify input = %+v", service.bindEmailVerifyInput)
	}
}

// A binding min=8 tag used to reject short passwords during decode, collapsing
// the documented 42201 into a generic 40000 and hiding the service's mapping.
// The service must own the length rule for every password entry point.
func TestShortPasswordReachesServiceForDocumentedCode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tooShort := &session.Error{Kind: session.KindValidationFailed, Code: errcode.CodePasswordTooShort}
	tests := []struct {
		name string
		path string
		body string
	}{
		{
			name: "reset-password",
			path: "/auth/reset-password",
			body: `{"login_email":"pt@sast.fun","code":"123456","new_password":"short"}`,
		},
		{
			name: "change-password",
			path: "/auth/change-password",
			body: `{"old_password":"oldpassword","new_password":"short"}`,
		},
		{
			name: "register",
			path: "/auth/register",
			body: `{"register_ticket":"reg_x","password":"short","name":"pt","student_id":"B24","phone_number":"13800138000","qq_number":"10000","college":"其他","major":"CS"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeService{resetPasswordErr: tooShort, changePasswordErr: tooShort, registerErr: tooShort}
			router := gin.New()
			RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuthWith(middleware.Principal{UserID: 42, JTI: "jti", ExpiresAt: time.Now().Add(time.Hour)})))
			recorder := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(recorder, request)

			body := decodeBody(t, recorder)
			if recorder.Code != http.StatusUnprocessableEntity || body.Code != errcode.CodePasswordTooShort {
				t.Fatalf("response = %d %#v, want 422 with code %d", recorder.Code, body, errcode.CodePasswordTooShort)
			}
		})
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
			RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuth()))
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

// Every protected /user write endpoint must thread the token's azp into the
// service input so the audit row can name the acting client. A handler that
// drops principal.ClientID silently regresses to actor_client_id = NULL for a
// delegated user:* token.
func TestUserEndpointsThreadActorClientID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	principal := middleware.Principal{UserID: 42, JTI: "jti", ClientID: "sast-people", ExpiresAt: time.Now().Add(time.Hour)}

	jsonRequest := func(method, path, body string) *http.Request {
		req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		return req
	}

	cases := []struct {
		name    string
		request func() *http.Request
		service *fakeService
		actor   func(*fakeService) string
	}{
		{
			name:    "logout",
			request: func() *http.Request { return jsonRequest(http.MethodPost, "/auth/logout", `{"refresh_token":"rt_x"}`) },
			service: &fakeService{logoutResult: &session.LogoutResult{BlacklistedJTI: "jti", FamilyID: "fam"}},
			actor:   func(s *fakeService) string { return s.logoutInput.ActorClientID },
		},
		{
			name: "change-password",
			request: func() *http.Request {
				return jsonRequest(http.MethodPost, "/auth/change-password", `{"old_password":"oldpassword","new_password":"newpassword"}`)
			},
			service: &fakeService{changePasswordResult: &session.ChangePasswordResult{UserID: 42}},
			actor:   func(s *fakeService) string { return s.changePasswordInput.ActorClientID },
		},
		{
			name:    "update-profile",
			request: func() *http.Request { return jsonRequest(http.MethodPut, "/user/profile", `{"nickname":"新昵称"}`) },
			service: &fakeService{updateProfileResult: &session.UpdateProfileResult{Profile: session.UserProfileDTO{ID: 42}}},
			actor:   func(s *fakeService) string { return s.updateProfileInput.ActorClientID },
		},
		{
			name:    "upload-avatar",
			request: func() *http.Request { return avatarMultipartRequest(t, testPNGBytes(t)) },
			service: &fakeService{uploadAvatarResult: &session.UploadAvatarResult{AvatarURL: "https://cdn.example.com/a.png"}},
			actor:   func(s *fakeService) string { return s.uploadAvatarInput.ActorClientID },
		},
		{
			name: "unbind-identity",
			request: func() *http.Request {
				return jsonRequest(http.MethodDelete, "/user/identities/5", `{"password":"secret"}`)
			},
			service: &fakeService{unbindIdentityResult: &session.UnbindIdentityResult{Provider: "other_mail", ProviderID: "x@qq.com"}},
			actor:   func(s *fakeService) string { return s.unbindIdentityInput.ActorClientID },
		},
		{
			name: "bind-email-send-code",
			request: func() *http.Request {
				return jsonRequest(http.MethodPost, "/user/identities/email", `{"email":"extra@qq.com"}`)
			},
			service: &fakeService{bindEmailSendCodeResult: &session.BindEmailSendCodeResult{BindTicket: "be_t", ExpiresIn: 300}},
			actor:   func(s *fakeService) string { return s.bindEmailSendCodeInput.ActorClientID },
		},
		{
			name: "bind-email-verify",
			request: func() *http.Request {
				return jsonRequest(http.MethodPost, "/user/identities/email/verify", `{"bind_ticket":"be_t","code":"123456"}`)
			},
			service: &fakeService{bindEmailVerifyResult: &session.BindEmailVerifyResult{Email: "extra@qq.com", Identity: session.IdentityDTO{}}},
			actor:   func(s *fakeService) string { return s.bindEmailVerifyInput.ActorClientID },
		},
		{
			name:    "logout-device",
			request: func() *http.Request { return jsonRequest(http.MethodDelete, "/user/devices/fam", ``) },
			service: &fakeService{logoutDeviceResult: &session.LogoutDeviceResult{DeviceID: "fam"}},
			actor:   func(s *fakeService) string { return s.logoutDeviceInput.ActorClientID },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			RegisterRoutes(router, Handler{Service: tc.service}, scopedGates(allowAuthWith(principal)))
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, tc.request())
			if recorder.Code != http.StatusOK {
				t.Fatalf("response = %d, want 200", recorder.Code)
			}
			if got := tc.actor(tc.service); got != "sast-people" {
				t.Fatalf("ActorClientID = %q, want sast-people (azp must reach the service input)", got)
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
			RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuth()))
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
	RegisterRoutes(router, Handler{Service: service, Clock: fixedClock{value: now}}, scopedGates(allowAuth()))
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
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuth()))
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

// scopedGates wraps an auth middleware with passthrough scope gates. Tests that
// exercise handler behavior rather than the scope gates themselves mount routes
// through this helper; the scope gates themselves are covered by
// middleware.TestRequireUserAuthAndDelegatedScope.
func scopedGates(auth gin.HandlerFunc) Gates {
	passthrough := func(c *gin.Context) { c.Next() }
	return Gates{RequireAuth: auth, RequireReadScope: passthrough, RequireWriteScope: passthrough}
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

func (s *fakeService) Card(_ context.Context, input session.CardInput) (*session.CardResult, error) {
	s.cardCalls++
	s.cardInput = input
	return s.cardResult, s.cardErr
}

func (s *fakeService) ListIdentities(_ context.Context, input session.ListIdentitiesInput) (*session.ListIdentitiesResult, error) {
	s.listIdentitiesInput = input
	return s.listIdentitiesResult, s.listIdentitiesErr
}

func (s *fakeService) UnbindIdentity(_ context.Context, input session.UnbindIdentityInput) (*session.UnbindIdentityResult, error) {
	s.unbindIdentityCalls++
	s.unbindIdentityInput = input
	return s.unbindIdentityResult, s.unbindIdentityErr
}

func (s *fakeService) ListDevices(_ context.Context, input session.ListDevicesInput) (*session.ListDevicesResult, error) {
	s.listDevicesCalls++
	s.listDevicesInput = input
	return s.listDevicesResult, s.listDevicesErr
}

func (s *fakeService) LogoutDevice(_ context.Context, input session.LogoutDeviceInput) (*session.LogoutDeviceResult, error) {
	s.logoutDeviceCalls++
	s.logoutDeviceInput = input
	return s.logoutDeviceResult, s.logoutDeviceErr
}
