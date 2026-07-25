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
}

type Handler struct {
	Service Service
	Clock   auth.Clock
}

type loginRequest struct {
	LoginEmail string `json:"login_email" binding:"required"`
	Password   string `json:"password" binding:"required"`
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
	protected := r.Group("")
	protected.Use(authMiddleware)
	protected.POST("/auth/logout", h.Logout)
	protected.GET("/user/profile", h.Profile)
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
	result, err := h.Service.Refresh(c.Request.Context(), session.RefreshInput{RefreshToken: req.RefreshToken})
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
