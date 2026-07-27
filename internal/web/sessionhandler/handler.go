package sessionhandler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
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
}

type Handler struct {
	Service Service
	Clock   auth.Clock
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
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
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

func RegisterRoutes(r gin.IRouter, h Handler, authMiddleware gin.HandlerFunc) {
	r.POST("/user/login", h.Login)
	r.POST("/auth/refresh", h.Refresh)
	r.POST("/auth/register/send-code", h.SendRegisterCode)
	r.POST("/auth/register/verify-code", h.VerifyRegisterCode)
	r.POST("/auth/register", h.Register)
	r.POST("/auth/forgot-password/send-code", h.ForgotPasswordSendCode)
	r.POST("/auth/reset-password", h.ResetPassword)
	protected := r.Group("")
	protected.Use(authMiddleware)
	protected.POST("/auth/logout", h.Logout)
	protected.POST("/auth/change-password", h.ChangePassword)
	protected.GET("/user/profile", h.Profile)
	protected.POST("/user/identities/email", h.BindEmailSendCode)
	protected.POST("/user/identities/email/verify", h.BindEmailVerify)
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
	result, err := h.Service.Refresh(c.Request.Context(), session.RefreshInput{
		RefreshToken: req.RefreshToken,
		ClientIP:     c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
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
		response.Error(c, &response.BusinessError{HTTPStatus: http.StatusInternalServerError, Code: errcode.CodeInternal, Message: "服务器内部错误"})
		return
	}
	var req logoutRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	if _, err := h.Service.Logout(c.Request.Context(), session.LogoutInput{
		PrincipalJTI:    principal.JTI,
		PrincipalUserID: principal.UserID,
		RefreshToken:    req.RefreshToken,
		ClientIP:        c.ClientIP(),
		UserAgent:       c.Request.UserAgent(),
	}); err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, logoutResponse{Message: "已登出"})
}

func (h Handler) Profile(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, &response.BusinessError{HTTPStatus: http.StatusInternalServerError, Code: errcode.CodeInternal, Message: "服务器内部错误"})
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
	response.Ok(c, messageResponse{Message: "密码重置成功，请重新登录"})
}

func (h Handler) ChangePassword(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, &response.BusinessError{HTTPStatus: http.StatusInternalServerError, Code: errcode.CodeInternal, Message: "服务器内部错误"})
		return
	}
	var req changePasswordRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	if _, err := h.Service.ChangePassword(c.Request.Context(), session.ChangePasswordInput{
		UserID:      principal.UserID,
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
		ClientIP:    c.ClientIP(),
		UserAgent:   c.Request.UserAgent(),
	}); err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, messageResponse{Message: "密码修改成功"})
}

func (h Handler) BindEmailSendCode(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, &response.BusinessError{HTTPStatus: http.StatusInternalServerError, Code: errcode.CodeInternal, Message: "服务器内部错误"})
		return
	}
	var req bindEmailRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Service.BindEmailSendCode(c.Request.Context(), session.BindEmailSendCodeInput{
		UserID:    principal.UserID,
		Email:     req.Email,
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
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
		response.Error(c, &response.BusinessError{HTTPStatus: http.StatusInternalServerError, Code: errcode.CodeInternal, Message: "服务器内部错误"})
		return
	}
	var req bindEmailVerifyRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Service.BindEmailVerify(c.Request.Context(), session.BindEmailVerifyInput{
		UserID:     principal.UserID,
		BindTicket: req.BindTicket,
		Code:       req.Code,
		ClientIP:   c.ClientIP(),
		UserAgent:  c.Request.UserAgent(),
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
	seconds := int64(expiry.Sub(now).Seconds())
	if seconds < 0 {
		return 0
	}
	return seconds
}

func badRequest() error {
	return &response.BusinessError{HTTPStatus: http.StatusBadRequest, Code: errcode.CodeBadRequest, Message: "请求参数错误"}
}
