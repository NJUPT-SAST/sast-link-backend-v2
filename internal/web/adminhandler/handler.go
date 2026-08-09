// Package adminhandler exposes the administrative console endpoints over HTTP.
package adminhandler

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminclient"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminuser"
)

// ClientService is the OAuth client registry use cases this handler exposes.
type ClientService interface {
	ListClients(ctx context.Context) ([]adminclient.Client, error)
	CreateClient(ctx context.Context, input adminclient.CreateClientInput) (*adminclient.CreateClientResult, error)
	UpdateClient(ctx context.Context, input adminclient.UpdateClientInput) (*adminclient.UpdateClientResult, error)
}

// UserService is the user-management use cases this handler exposes.
type UserService interface {
	ListUsers(ctx context.Context, input adminuser.ListUsersInput) (*adminuser.ListUsersResult, error)
	GetUser(ctx context.Context, userID int64) (*adminuser.UserDetail, error)
	UpdateUser(ctx context.Context, input adminuser.UpdateUserInput) (*adminuser.UpdateUserResult, error)
	DeleteUser(ctx context.Context, input adminuser.TargetUserInput) error
	RestoreUser(ctx context.Context, input adminuser.TargetUserInput) error
	// Stats returns the aggregate account counts for the console overview.
	Stats(ctx context.Context) (repository.UserStats, error)
}

// AuditLogService is the audit-trail query this handler exposes.
type AuditLogService interface {
	ListAuditLogs(ctx context.Context, input adminuser.ListAuditLogsInput) (*adminuser.ListAuditLogsResult, error)
}

// Handler serves the admin console endpoints.
type Handler struct {
	Clients   ClientService
	Users     UserService
	AuditLogs AuditLogService
}

// RegisterRoutes mounts the admin endpoints.
//
// requireAuth must precede the role gates: they read the Principal that
// authentication puts in the context. All three are passed in rather than built
// here so the composition root stays the only place that decides how
// authentication works.
//
// Two role gates rather than one, because PRD §4.12 splits the console: a lecturer
// may read the user list and detail, everything else is admin-only. The group
// carries authentication alone and each route names the gate it needs, so a new
// route with no gate fails to compile a permission by omission — it simply has
// none, which is why every route below states one explicitly.
//
// Third-party OAuth tokens cannot reach any of these: RequireAuth's azp gate
// rejects them before a role check runs.
func RegisterRoutes(r gin.IRouter, h Handler, requireAuth, requireAdmin, requireReader gin.HandlerFunc) {
	admin := r.Group("/admin", requireAuth)
	admin.GET("/oauth-clients", requireAdmin, h.ListClients)
	admin.POST("/oauth-clients", requireAdmin, h.CreateClient)
	admin.PUT("/oauth-clients/:id", requireAdmin, h.UpdateClient)

	admin.GET("/users", requireReader, h.ListUsers)
	admin.GET("/users/:id", requireReader, h.GetUser)
	admin.PUT("/users/:id", requireAdmin, h.UpdateUser)
	admin.DELETE("/users/:id", requireAdmin, h.DeleteUser)
	admin.PUT("/users/:id/restore", requireAdmin, h.RestoreUser)

	admin.GET("/audit-logs", requireAdmin, h.ListAuditLogs)

	admin.GET("/stats", requireAdmin, h.Stats)
}

// AdminRole is the role permitted on the write endpoints, exported so the
// composition root cannot silently mount them behind a different one.
const AdminRole = model.UserRoleAdmin

// ReaderRoles are the roles permitted on the read-only user endpoints. Exported
// for the same reason as AdminRole: the set of roles that may read the directory
// is a contract decision, not a wiring detail.
var ReaderRoles = []model.UserRole{model.UserRoleAdmin, model.UserRoleLecturer}
