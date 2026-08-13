package sessionhandler

import (
	"context"
	"math"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

type Service interface {
	Login(ctx context.Context, input session.LoginInput) (*session.LoginResult, error)
	Refresh(ctx context.Context, input session.RefreshInput) (*session.RefreshResult, error)
	Logout(ctx context.Context, input session.LogoutInput) (*session.LogoutResult, error)
	Profile(ctx context.Context, input session.ProfileInput) (*session.ProfileResult, error)
	SendRegisterCode(ctx context.Context, input session.SendRegisterCodeInput) (*session.SendRegisterCodeResult, error)
	VerifyRegisterCode(ctx context.Context, input session.VerifyRegisterCodeInput) (*session.VerifyRegisterCodeResult, error)
	Register(ctx context.Context, input session.RegisterInput) (*session.RegisterResult, error)
	ForgotPasswordSendCode(ctx context.Context, input session.ForgotPasswordInput) (*session.ForgotPasswordResult, error)
	ResetPassword(ctx context.Context, input session.ResetPasswordInput) (*session.ResetPasswordResult, error)
	ChangePassword(ctx context.Context, input session.ChangePasswordInput) (*session.ChangePasswordResult, error)
	BindEmailSendCode(ctx context.Context, input session.BindEmailSendCodeInput) (*session.BindEmailSendCodeResult, error)
	BindEmailVerify(ctx context.Context, input session.BindEmailVerifyInput) (*session.BindEmailVerifyResult, error)
	UpdateProfile(ctx context.Context, input session.UpdateProfileInput) (*session.UpdateProfileResult, error)
	UploadAvatar(ctx context.Context, input session.UploadAvatarInput) (*session.UploadAvatarResult, error)
	ListIdentities(ctx context.Context, input session.ListIdentitiesInput) (*session.ListIdentitiesResult, error)
	UnbindIdentity(ctx context.Context, input session.UnbindIdentityInput) (*session.UnbindIdentityResult, error)
	ListDevices(ctx context.Context, input session.ListDevicesInput) (*session.ListDevicesResult, error)
	LogoutDevice(ctx context.Context, input session.LogoutDeviceInput) (*session.LogoutDeviceResult, error)
	Card(ctx context.Context, input session.CardInput) (*session.CardResult, error)
}

type Handler struct {
	Service Service
	Clock   auth.Clock
	// Cookies writes/reads the httpOnly session cookie (refresh token) that a
	// fresh tab uses to bootstrap a session. Nil in tests that don't exercise
	// the cookie flow; handlers skip cookie handling when it is.
	Cookies *middleware.SessionCookie
}

type loginRequest struct {
	LoginEmail string `json:"login_email" binding:"required"`
	Password   string `json:"password" binding:"required"`
}

type sendRegisterCodeRequest struct {
	LoginEmail string `json:"login_email" binding:"required,email"`
}

type verifyRegisterCodeRequest struct {
	LoginEmail string `json:"login_email" binding:"required,email"`
	Code       string `json:"code" binding:"required"`
}

// Password length is deliberately not enforced by a binding tag here: the
// documented contract returns 42201 (密码长度不足) for a short password, and a
// binding failure would collapse that into a generic 40000. The session service
// owns the rule for every password entry point.
type registerRequest struct {
	RegisterTicket    string `json:"register_ticket" binding:"required"`
	Password          string `json:"password" binding:"required"`
	Name              string `json:"name" binding:"required"`
	StudentID         string `json:"student_id" binding:"required"`
	PhoneNumber       string `json:"phone_number" binding:"required"`
	QQNumber          string `json:"qq_number" binding:"required"`
	College           string `json:"college" binding:"required"`
	Major             string `json:"major" binding:"required"`
	RegistrationState string `json:"registration_state"`
	OAuthState        string `json:"oauth_state"`
}

type forgotPasswordRequest struct {
	LoginEmail string `json:"login_email" binding:"required,email"`
}

type resetPasswordRequest struct {
	LoginEmail  string `json:"login_email" binding:"required,email"`
	Code        string `json:"code" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type bindEmailRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type bindEmailVerifyRequest struct {
	BindTicket string `json:"bind_ticket" binding:"required"`
	Code       string `json:"code" binding:"required"`
}

type refreshRequest struct {
	// Optional: a fresh tab sends an empty body and the httpOnly session cookie
	// is the refresh credential instead.
	RefreshToken string `json:"refresh_token"`
}

type logoutRequest struct {
	// Accepted for contract compatibility (the frontend sends an empty object
	// now); the service revokes the authenticated access token's own family, so
	// the refresh token is no longer consulted.
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type loginResponse struct {
	tokenResponse
	User authUserDTO `json:"user"`
}

type logoutResponse struct {
	Message string `json:"message"`
}

type sendCodeResponse struct {
	Message   string `json:"message"`
	ExpiresIn int    `json:"expires_in"`
}

type verifyRegisterCodeResponse struct {
	RegisterTicket string `json:"register_ticket"`
	ExpiresIn      int    `json:"expires_in"`
}

type registerResponse struct {
	tokenResponse
	User authUserDTO `json:"user"`
}

type messageResponse struct {
	Message string `json:"message"`
}

type bindEmailResponse struct {
	BindTicket string `json:"bind_ticket"`
	ExpiresIn  int    `json:"expires_in"`
}

type bindEmailVerifyResponse struct {
	Message  string      `json:"message"`
	Identity identityDTO `json:"identity"`
}

type authUserDTO struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	LoginEmail string    `json:"login_email"`
	Role       string    `json:"role"`
	State      string    `json:"state"`
	EmailType  string    `json:"email_type"`
	CreatedAt  time.Time `json:"created_at"`
}

type profileDTO struct {
	ID          int64             `json:"id"`
	Name        string            `json:"name"`
	LoginEmail  string            `json:"login_email"`
	Role        string            `json:"role"`
	State       string            `json:"state"`
	EmailType   string            `json:"email_type"`
	PhoneNumber string            `json:"phone_number"`
	QQNumber    string            `json:"qq_number"`
	StudentID   string            `json:"student_id"`
	College     string            `json:"college"`
	Major       string            `json:"major"`
	Profile     *profileDetailDTO `json:"profile"`
	Identities  []identityDTO     `json:"identities"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type profileDetailDTO struct {
	Nickname   *string   `json:"nickname"`
	Department *string   `json:"department"`
	Intro      *string   `json:"intro"`
	Email      *string   `json:"email"`
	Avatar     *string   `json:"avatar"`
	BlogURL    *string   `json:"blog_url"`
	GitHubURL  *string   `json:"github_url"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type identityDTO struct {
	ID             int64      `json:"id"`
	Provider       string     `json:"provider"`
	ProviderID     string     `json:"provider_id"`
	IdentityData   any        `json:"identity_data"`
	TokenExpiresAt *time.Time `json:"token_expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// Gates are the middleware the protected /user routes are mounted behind. They
// are passed in rather than built here so the composition root stays the only
// place that decides how authentication works.
//
// A struct rather than positional parameters: three adjacent gin.HandlerFuncs,
// and a transposed pair would compile into a route gated by the wrong
// permission.
type Gates struct {
	// RequireAuth authenticates the group. On the /user surface this is the
	// scoped gate (RequireUserAuth), not the strict internal-client one.
	RequireAuth gin.HandlerFunc
	// RequireReadScope and RequireWriteScope bound what a scoped token
	// may do. They are no-ops for an internal console token, whose ceiling is
	// unchanged.
	RequireReadScope  gin.HandlerFunc
	RequireWriteScope gin.HandlerFunc
}

// ReadScopes and WriteScopes are the scoped access each class of
// /user route accepts, exported for the same reason adminhandler exports its
// counterparts: the set of scopes that may read or write a user's own record is
// a contract decision, not a wiring detail.
//
// user:write appears in ReadScopes because write implies read, mirroring the
// admin routes: a delegate trusted to modify a user's own record is not
// meaningfully restrained by being refused a read of it.
var (
	ReadScopes  = []string{scope.UserRead, scope.UserWrite}
	WriteScopes = []string{scope.UserWrite}
)

func RegisterRoutes(r gin.IRouter, h Handler, g Gates) {
	// Fail at boot rather than serve an ungated /user route. gin would happily
	// mount a nil handler and panic on the first request instead.
	if g.RequireAuth == nil || g.RequireReadScope == nil || g.RequireWriteScope == nil {
		panic("sessionhandler: every gate in Gates must be set")
	}

	r.POST("/user/login", h.Login)
	r.POST("/auth/refresh", h.Refresh)
	r.POST("/auth/register/send-code", h.SendRegisterCode)
	r.POST("/auth/register/verify-code", h.VerifyRegisterCode)
	r.POST("/auth/register", h.Register)
	r.POST("/auth/forgot-password/send-code", h.ForgotPasswordSendCode)
	r.POST("/auth/reset-password", h.ResetPassword)
	// The card endpoint is temporarily disabled pending a privacy redesign. Its
	// sequential-ID public URL lets anyone enumerate the full member roster, which
	// is no longer acceptable; it will be reworked (owner-only + non-enumerable
	// identifier), not re-enabled as-is. The handler/service/repository code stays
	// in place pending that redesign, and the OIDC profile claim has been removed
	// so no client can read the card projection through it either.
	// r.GET("/card/:id", h.Card)

	// Every protected route names a scope gate explicitly. A new route that names
	// none has no scoped-client permission rather than inheriting one. The
	// internal console token is exempt from every scope gate (its ceiling is
	// being an authenticated session), so the console keeps its current access to
	// all of these endpoints.
	protected := r.Group("")
	protected.Use(g.RequireAuth)
	protected.GET("/user/profile", g.RequireReadScope, h.Profile)
	protected.PUT("/user/profile", g.RequireWriteScope, h.UpdateProfile)
	protected.PUT("/user/avatar", g.RequireWriteScope, h.UploadAvatar)
	protected.GET("/user/identities", g.RequireReadScope, h.ListIdentities)
	protected.POST("/user/identities/email", g.RequireWriteScope, h.BindEmailSendCode)
	protected.POST("/user/identities/email/verify", g.RequireWriteScope, h.BindEmailVerify)
	protected.DELETE("/user/identities/:id", g.RequireWriteScope, h.UnbindIdentity)
	protected.GET("/user/devices", g.RequireReadScope, h.ListDevices)
	protected.DELETE("/user/devices/:id", g.RequireWriteScope, h.LogoutDevice)
	protected.POST("/auth/logout", g.RequireWriteScope, h.Logout)
	protected.POST("/auth/change-password", g.RequireWriteScope, h.ChangePassword)
}

func (h Handler) Login(c *gin.Context) {
	var req loginRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Service.Login(c.Request.Context(), session.LoginInput{
		Identifier: req.LoginEmail,
		Password:   req.Password,
		ClientIP:   c.ClientIP(),
		UserAgent:  c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	h.setSessionCookie(c, result.RefreshToken, result.RefreshExpiresAt)
	response.Ok(c, loginResponse{
		tokenResponse: tokenResponse{
			AccessToken:  result.AccessToken,
			RefreshToken: result.RefreshToken,
			TokenType:    result.TokenType,
			ExpiresIn:    expiresIn(h.now(), result.AccessExpiresAt),
		},
		User: mapAuthUser(result.Profile),
	})
}

func (h Handler) Refresh(c *gin.Context) {
	var req refreshRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	refreshToken := req.RefreshToken
	fromCookie := false
	if refreshToken == "" {
		// A fresh tab holds no sessionStorage token, but the httpOnly session
		// cookie — set at login/refresh — is the refresh credential.
		refreshToken = h.readSessionCookie(c)
		fromCookie = refreshToken != ""
	}
	if refreshToken == "" {
		response.Error(c, unauthorized())
		return
	}
	result, err := h.Service.Refresh(c.Request.Context(), session.RefreshInput{
		RefreshToken: refreshToken,
		ClientIP:     c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})
	if err != nil {
		mapped := mapServiceError(err)
		// Clear a stale cookie only when the dead token actually came from it,
		// and only for a definitively dead family — whitelisted codes. A benign
		// concurrent refresh (another tab rotated the same cookie within the grace
		// window) must keep the cookie, it now holds the winner's token; a body
		// token that failed must not delete a healthy newer cookie (this also
		// makes a cross-site POST, which carries no cookie, a no-op instead of a
		// cookie-clearing CSRF); transient failures (429/500) never clear. The
		// whitelist is forward-safe: a future 401 code that does not mean "the
		// family is gone" defaults to keeping the cookie rather than wiping a
		// possibly-healthy session.
		if be, ok := mapped.(*response.BusinessError); ok && fromCookie {
			switch be.Code {
			case errcode.CodeAccessTokenInvalid, errcode.CodeAccountDeleted:
				h.clearSessionCookie(c)
			}
		}
		response.Error(c, mapped)
		return
	}
	// Refresh always rotates the refresh token, so the cookie must follow the
	// new value — otherwise the next bootstrap reads a dead token and replay
	// detection cuts the whole family.
	h.setSessionCookie(c, result.RefreshToken, result.RefreshExpiresAt)
	response.Ok(c, tokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    result.TokenType,
		ExpiresIn:    expiresIn(h.now(), result.AccessExpiresAt),
	})
}

func (h Handler) Logout(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	var req logoutRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	// The service revokes the authenticated session's own family (from the
	// access token), so a refresh token is not required. The body may still
	// carry one (the frontend sends an empty object now); it is ignored.
	if _, err := h.Service.Logout(c.Request.Context(), session.LogoutInput{
		PrincipalJTI:    principal.JTI,
		PrincipalUserID: principal.UserID,
		ActorClientID:   principal.ClientID,
		ClientIP:        c.ClientIP(),
		UserAgent:       c.Request.UserAgent(),
	}); err != nil {
		mapped := mapServiceError(err)
		// A dead access token (revoked/expired under the service's clock, within
		// the TOCTOU window between the middleware's DB check and here) means the
		// session is already gone. Logout stays idempotent — clear the dead
		// cookie and report success, so a session that died mid-request never
		// leaves the user stuck. The whitelist is by code, not HTTP status, so a
		// future 401 semantics that does not mean "the session is dead" defaults
		// to surfacing the error with the cookie intact.
		if be, ok := mapped.(*response.BusinessError); ok && be.Code == errcode.CodeAccessTokenInvalid {
			h.clearSessionCookie(c)
			response.Ok(c, logoutResponse{Message: "已登出"})
			return
		}
		response.Error(c, mapped)
		return
	}
	// The session cookie is part of the same session family — drop it so the
	// browser cannot bootstrap a dead session from a fresh tab.
	h.clearSessionCookie(c)
	response.Ok(c, logoutResponse{Message: "已登出"})
}

func (h Handler) Profile(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	result, err := h.Service.Profile(c.Request.Context(), session.ProfileInput{UserID: principal.UserID})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, mapProfile(result.Profile))
}

func (h Handler) SendRegisterCode(c *gin.Context) {
	var req sendRegisterCodeRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Service.SendRegisterCode(c.Request.Context(), session.SendRegisterCodeInput{
		Email:     req.LoginEmail,
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, sendCodeResponse{Message: "验证码已发送至邮箱", ExpiresIn: result.ExpiresIn})
}

func (h Handler) VerifyRegisterCode(c *gin.Context) {
	var req verifyRegisterCodeRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Service.VerifyRegisterCode(c.Request.Context(), session.VerifyRegisterCodeInput{
		Email:     req.LoginEmail,
		Code:      req.Code,
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, verifyRegisterCodeResponse{RegisterTicket: result.RegisterTicket, ExpiresIn: result.ExpiresIn})
}

func (h Handler) Register(c *gin.Context) {
	var req registerRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Service.Register(c.Request.Context(), session.RegisterInput{
		RegisterTicket:    req.RegisterTicket,
		Password:          req.Password,
		Name:              req.Name,
		StudentID:         req.StudentID,
		PhoneNumber:       req.PhoneNumber,
		QQNumber:          req.QQNumber,
		College:           req.College,
		Major:             req.Major,
		RegistrationState: req.RegistrationState,
		OAuthState:        req.OAuthState,
		ClientIP:          c.ClientIP(),
		UserAgent:         c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	h.setSessionCookie(c, result.RefreshToken, result.RefreshExpiresAt)
	response.Created(c, registerResponse{
		tokenResponse: tokenResponse{
			AccessToken:  result.AccessToken,
			RefreshToken: result.RefreshToken,
			TokenType:    result.TokenType,
			ExpiresIn:    expiresIn(h.now(), result.AccessExpiresAt),
		},
		User: mapAuthUser(result.Profile),
	})
}

func (h Handler) ForgotPasswordSendCode(c *gin.Context) {
	var req forgotPasswordRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Service.ForgotPasswordSendCode(c.Request.Context(), session.ForgotPasswordInput{
		Email:     req.LoginEmail,
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, sendCodeResponse{Message: "重置密码请求已受理", ExpiresIn: result.ExpiresIn})
}

func (h Handler) ResetPassword(c *gin.Context) {
	var req resetPasswordRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	if _, err := h.Service.ResetPassword(c.Request.Context(), session.ResetPasswordInput{
		Email:     req.LoginEmail,
		Code:      req.Code,
		Password:  req.NewPassword,
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	}); err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	// Reset-password revokes every session the user holds (like change-password);
	// clear the browser's session cookie so it cannot bootstrap a dead session.
	h.clearSessionCookie(c)
	response.Ok(c, messageResponse{Message: "密码重置成功，请重新登录"})
}

func (h Handler) ChangePassword(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	var req changePasswordRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	if _, err := h.Service.ChangePassword(c.Request.Context(), session.ChangePasswordInput{
		UserID:        principal.UserID,
		OldPassword:   req.OldPassword,
		NewPassword:   req.NewPassword,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	}); err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	// Change-password revokes every session the user holds; clear the browser's
	// session cookie too so it cannot bootstrap one of those dead sessions.
	h.clearSessionCookie(c)
	response.Ok(c, messageResponse{Message: "密码修改成功"})
}

func (h Handler) BindEmailSendCode(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	var req bindEmailRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Service.BindEmailSendCode(c.Request.Context(), session.BindEmailSendCodeInput{
		UserID:        principal.UserID,
		Email:         req.Email,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, bindEmailResponse{BindTicket: result.BindTicket, ExpiresIn: result.ExpiresIn})
}

func (h Handler) BindEmailVerify(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	var req bindEmailVerifyRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Service.BindEmailVerify(c.Request.Context(), session.BindEmailVerifyInput{
		UserID:        principal.UserID,
		BindTicket:    req.BindTicket,
		Code:          req.Code,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, bindEmailVerifyResponse{Message: "邮箱绑定成功", Identity: mapIdentity(result.Identity)})
}

func (h Handler) now() time.Time {
	if h.Clock != nil {
		return h.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

func expiresIn(now, expiry time.Time) int64 {
	// Ceil so a token expiring in 3599.9s reports 3600, matching the OAuth token
	// endpoint; truncation would under-report the same TTL by one second.
	seconds := int64(math.Ceil(expiry.Sub(now).Seconds()))
	if seconds < 0 {
		return 0
	}
	return seconds
}

func badRequest() error {
	return &response.BusinessError{HTTPStatus: http.StatusBadRequest, Code: errcode.CodeBadRequest, Message: "请求参数错误"}
}

func unauthorized() error {
	return &response.BusinessError{HTTPStatus: http.StatusUnauthorized, Code: errcode.CodeUnauthenticated, Message: "未登录"}
}

func internalError() error {
	return &response.BusinessError{HTTPStatus: http.StatusInternalServerError, Code: errcode.CodeInternal, Message: "服务器内部错误"}
}

// setSessionCookie writes the httpOnly session cookie for a freshly issued
// refresh token, scoped to its remaining lifetime (computed against the same
// injected clock the response's expires_in uses). A zero or past expiry is a
// no-op inside middleware.SessionCookie.Set — never a silent clear.
func (h Handler) setSessionCookie(c *gin.Context, refreshToken string, expiresAt time.Time) {
	h.Cookies.Set(c, refreshToken, expiresAt.Sub(h.now()))
}

// clearSessionCookie deletes the session cookie (logout, password change).
func (h Handler) clearSessionCookie(c *gin.Context) {
	h.Cookies.Clear(c)
}

// readSessionCookie returns the session cookie value, or "" when unset.
func (h Handler) readSessionCookie(c *gin.Context) string {
	return h.Cookies.Read(c)
}
