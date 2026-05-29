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

func NewAuthHandler(registerSvc *service.RegisterService) *AuthHandler {
	return &AuthHandler{registerSvc: registerSvc}
}

// SendEmail handles POST /sendEmail
func (h *AuthHandler) SendEmail(c *gin.Context) {
	var req dto.SendEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Err(c, domain.ErrInvalidParams, "请提供有效的邮箱地址")
		return
	}

	if err := h.registerSvc.SendVerificationEmail(c.Request.Context(), req.Email); err != nil {
		var appErr *domain.AppError
		if errors.As(err, &appErr) {
			response.Err(c, appErr.Code, appErr.Message)
			return
		}
		response.Err(c, domain.ErrInternal, "发送验证码失败")
		return
	}

	response.OK(c, nil)
}

// Register handles POST /user/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req dto.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Err(c, domain.ErrInvalidParams, "请填写完整的注册信息")
		return
	}

	user, err := h.registerSvc.Register(c.Request.Context(), req)
	if err != nil {
		var appErr *domain.AppError
		if errors.As(err, &appErr) {
			response.Err(c, appErr.Code, appErr.Message)
			return
		}
		response.Err(c, domain.ErrInternal, "注册失败")
		return
	}

	response.OK(c, gin.H{
		"userId":     user.ID,
		"loginEmail": user.LoginEmail,
	})
}
