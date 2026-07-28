package sessionhandler

import (
	"github.com/gin-gonic/gin"

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
