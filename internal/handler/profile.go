package handler

import (
	"errors"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/dto"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/pkg/response"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service"
)

// ProfileHandler handles profile endpoints.
type ProfileHandler struct {
	profileSvc *service.ProfileService
}

// NewProfileHandler creates a new ProfileHandler.
func NewProfileHandler(profileSvc *service.ProfileService) *ProfileHandler {
	return &ProfileHandler{profileSvc: profileSvc}
}

// GetProfile handles GET /profile
// TODO: extract userID from JWT/session middleware once auth is implemented
func (h *ProfileHandler) GetProfile(c *gin.Context) {
	userID := currentUserID(c)
	if userID == 0 {
		response.Err(c, domain.ErrPermissionDenied, "未登录")
		return
	}

	profile, err := h.profileSvc.GetProfile(c.Request.Context(), userID)
	if err != nil {
		var appErr *domain.AppError
		if errors.As(err, &appErr) {
			response.Err(c, appErr.Code, appErr.Message)
			return
		}
		response.Err(c, domain.ErrInternal, "获取资料失败")
		return
	}

	response.OK(c, profile)
}

// UpdateProfile handles POST /profile/changeProfile
func (h *ProfileHandler) UpdateProfile(c *gin.Context) {
	userID := currentUserID(c)
	if userID == 0 {
		response.Err(c, domain.ErrPermissionDenied, "未登录")
		return
	}

	var req dto.ChangeProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Err(c, domain.ErrInvalidParams, "请求参数无效")
		return
	}

	if err := h.profileSvc.UpdateProfile(c.Request.Context(), userID, &req); err != nil {
		var appErr *domain.AppError
		if errors.As(err, &appErr) {
			response.Err(c, appErr.Code, appErr.Message)
			return
		}
		response.Err(c, domain.ErrInternal, "更新资料失败")
		return
	}

	response.OK(c, nil)
}

// currentUserID extracts the authenticated user ID from request context.
// TODO: replace with real JWT/session middleware extraction.
func currentUserID(c *gin.Context) int64 {
	uid, exists := c.Get("userID")
	if !exists {
		return 0
	}
	id, ok := uid.(int64)
	if !ok {
		return 0
	}
	return id
}
