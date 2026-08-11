package oauthhandler

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

// Grants lists the applications the signed-in user has authorized.
func (h Handler) Grants(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	grants, err := h.Service.Grants(c.Request.Context(), principal.UserID)
	if err != nil {
		response.Error(c, mapGrantsError(err))
		return
	}
	response.Ok(c, gin.H{"grants": grants})
}

// RevokeGrant removes one application's access for the signed-in user.
func (h Handler) RevokeGrant(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	clientID, err := strconv.ParseInt(c.Param("client_id"), 10, 64)
	if err != nil || clientID <= 0 {
		response.Error(c, badRequest())
		return
	}
	if err := h.Service.RevokeGrant(c.Request.Context(), principal.UserID, clientID, principal.ClientID); err != nil {
		response.Error(c, mapGrantsError(err))
		return
	}
	response.Ok(c, gin.H{"message": "已撤销该应用的授权"})
}
