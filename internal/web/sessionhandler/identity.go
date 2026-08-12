package sessionhandler

import (
	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

type identitiesListResponse struct {
	Identities []identityDTO `json:"identities"`
}

func (h Handler) ListIdentities(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	result, err := h.Service.ListIdentities(c.Request.Context(), session.ListIdentitiesInput{
		UserID: principal.UserID,
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	identities := make([]identityDTO, 0, len(result.Identities))
	for _, identity := range result.Identities {
		identities = append(identities, mapIdentity(identity))
	}
	response.Ok(c, identitiesListResponse{Identities: identities})
}

type unbindIdentityRequest struct {
	Password string `json:"password" binding:"required"`
}

func (h Handler) UnbindIdentity(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	identityID, ok := parsePositiveID(c.Param("id"))
	if !ok {
		// A non-numeric or non-positive path segment names no binding the caller
		// could own, so it gets the same 404xx as somebody else's ID rather than a
		// 400 that confirms the difference.
		response.Error(c, notFound(errcode.CodeNotFound, "绑定记录不存在"))
		return
	}
	var req unbindIdentityRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	if _, err := h.Service.UnbindIdentity(c.Request.Context(), session.UnbindIdentityInput{
		UserID:        principal.UserID,
		IdentityID:    identityID,
		Password:      req.Password,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	}); err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, messageResponse{Message: "解绑成功"})
}
