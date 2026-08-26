package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

// RequireRole admits only principals holding one of the allowed roles.
//
// Must be chained after RequireAuth, which puts the Principal in the context; a
// missing Principal is a wiring mistake and reports as an internal error, not a
// permission denial.
//
// The role comes from the database row, not the token's role claim, so a
// demotion takes effect on the next request.
//
// An empty allowed set rejects every request, so a wiring slip surfaces as a
// visible 403 rather than a silently open admin endpoint.
func (a Authenticator) RequireRole(allowed ...model.UserRole) gin.HandlerFunc {
	permitted := make(map[string]struct{}, len(allowed))
	for _, role := range allowed {
		permitted[string(role)] = struct{}{}
	}
	return func(c *gin.Context) {
		principal, ok := PrincipalFrom(c)
		if !ok {
			response.Error(c, backendError())
			c.Abort()
			return
		}
		if _, allow := permitted[principal.Role]; !allow {
			response.Error(c, authBusinessError(http.StatusForbidden, errcode.CodeForbidden, "无权限"))
			c.Abort()
			return
		}
		c.Next()
	}
}
