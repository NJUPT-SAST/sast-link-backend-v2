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
// Must be chained after RequireAuth, which is what puts the Principal in the
// context; a missing Principal means the two are wired in the wrong order and is
// reported as an internal error rather than as a permission denial, because it is
// a programming mistake and not something the caller did.
//
// The role is read from the Principal, which the authenticator populates from the
// database row rather than from the token's role claim — see authenticate. A
// demotion therefore takes effect on the next request.
//
// An empty allowed set rejects every request. The alternative reading, "no
// constraint means allow all", turns a wiring slip into a silently open admin
// endpoint; failing closed makes it a visible 403 instead.
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
