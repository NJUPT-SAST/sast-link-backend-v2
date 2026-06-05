// Package handler implements HTTP handlers for the SAST Link API.
package handler

import (
	"errors"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/dto"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/pkg/response"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	registerSvc *service.RegisterService
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(registerSvc *service.RegisterService) *AuthHandler {
	return &AuthHandler{registerSvc: registerSvc}
}

// SendRegisterCode handles POST /auth/register/send-code
func (h *AuthHandler) SendRegisterCode(c *gin.Context) {
	var req dto.SendCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Err(c, domain.ErrInvalidParams, "请提供有效的邮箱地址")
		return
	}

	if err := h.registerSvc.SendVerificationCode(c.Request.Context(), req.LoginEmail); err != nil {
		var appErr *domain.AppError
		if errors.As(err, &appErr) {
			response.Err(c, appErr.Code, appErr.Message)
			return
		}
		response.Err(c, domain.ErrEmailSendFailed, "发送验证码失败")
		return
	}

	response.OK(c, dto.SendCodeResponse{
		Message:   "验证码已发送至邮箱",
		ExpiresIn: 300,
	})
}

// VerifyRegisterCode handles POST /auth/register/verify-code
func (h *AuthHandler) VerifyRegisterCode(c *gin.Context) {
	var req dto.VerifyRegisterCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Err(c, domain.ErrInvalidParams, "请提供邮箱和验证码")
		return
	}

	ticket, err := h.registerSvc.VerifyCode(c.Request.Context(), req.LoginEmail, req.Code)
	if err != nil {
		var appErr *domain.AppError
		if errors.As(err, &appErr) {
			response.Err(c, appErr.Code, appErr.Message)
			return
		}
		response.Err(c, domain.ErrInternal, "验证码校验失败")
		return
	}

	response.OK(c, dto.RegisterTicketResponse{
		RegisterTicket: ticket,
		ExpiresIn:      300,
	})
}

// CompleteRegister handles POST /auth/register
func (h *AuthHandler) CompleteRegister(c *gin.Context) {
	var req dto.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Err(c, domain.ErrInvalidParams, "请填写完整的注册信息")
		return
	}

	user, err := h.registerSvc.Register(c.Request.Context(), &req)
	if err != nil {
		var appErr *domain.AppError
		if errors.As(err, &appErr) {
			response.Err(c, appErr.Code, appErr.Message)
			return
		}
		response.Err(c, domain.ErrInternal, "注册失败")
		return
	}

	// Note: Token issuance will be added when JWT service is implemented.
	response.Created(c, dto.TokenPair{
		AccessToken:  "", // TODO: issue JWT
		RefreshToken: "", // TODO: issue refresh token
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		User: dto.AuthUser{
			ID:         user.ID,
			LoginEmail: user.LoginEmail,
			Name:       user.Name,
			Role:       string(user.Role),
			State:      string(user.State),
			EmailType:  string(user.EmailType),
			CreatedAt:  user.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
	})
}
