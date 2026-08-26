package sessionhandler

import (
	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

// updateProfileRequest mirrors the PUT /user/profile body. Every field is a
// pointer so an absent key ("leave unchanged") stays distinguishable from an
// explicit empty string ("clear this display field").
//
// Lengths and enum membership are checked by the service, not by binding tags,
// so a violation answers with the documented 40000-plus-message rather than a
// generic binding failure.
type updateProfileRequest struct {
	Name        *string `json:"name"`
	PhoneNumber *string `json:"phone_number"`
	QQNumber    *string `json:"qq_number"`
	StudentID   *string `json:"student_id"`
	College     *string `json:"college"`
	Major       *string `json:"major"`
	Nickname    *string `json:"nickname"`
	Department  *string `json:"department"`
	Intro       *string `json:"intro"`
	Email       *string `json:"email"`
	BlogURL     *string `json:"blog_url"`
	GitHubURL   *string `json:"github_url"`
}

type updateProfileResponse struct {
	Message string     `json:"message"`
	User    profileDTO `json:"user"`
}

func (h Handler) UpdateProfile(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	var req updateProfileRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Service.UpdateProfile(c.Request.Context(), session.UpdateProfileInput{
		UserID:        principal.UserID,
		ActorClientID: principal.ClientID,
		Name:          req.Name,
		PhoneNumber:   req.PhoneNumber,
		QQNumber:      req.QQNumber,
		StudentID:     req.StudentID,
		College:       req.College,
		Major:         req.Major,
		Nickname:      req.Nickname,
		Department:    req.Department,
		Intro:         req.Intro,
		Email:         req.Email,
		BlogURL:       req.BlogURL,
		GitHubURL:     req.GitHubURL,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, updateProfileResponse{
		Message: "个人信息更新成功",
		User:    mapProfile(result.Profile),
	})
}
