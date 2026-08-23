// Package adminhandler exposes the administrative console endpoints over HTTP.
package adminhandler

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminclient"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminuser"
)

// ClientService is the OAuth client registry use cases this handler exposes.
type ClientService interface {
	ListClients(ctx context.Context) ([]adminclient.Client, error)
	CreateClient(ctx context.Context, input adminclient.CreateClientInput) (*adminclient.CreateClientResult, error)
	UpdateClient(ctx context.Context, input adminclient.UpdateClientInput) (*adminclient.UpdateClientResult, error)
	DeleteClient(ctx context.Context, input adminclient.DeleteClientInput) (*adminclient.DeleteClientResult, error)
	RotateClientSecret(ctx context.Context, input adminclient.RotateClientSecretInput) (*adminclient.RotateClientSecretResult, error)
}

// UserService is the user-management use cases this handler exposes.
type UserService interface {
	ListUsers(ctx context.Context, input adminuser.ListUsersInput) (*adminuser.ListUsersResult, error)
	GetUser(ctx context.Context, userID int64) (*adminuser.UserDetail, error)
	GetUsersByIDs(ctx context.Context, input adminuser.GetUsersByIDsInput) ([]adminuser.UserDetail, error)
	CreateUser(ctx context.Context, input adminuser.CreateUserInput) (*adminuser.CreateUserResult, error)
	UpdateUser(ctx context.Context, input adminuser.UpdateUserInput) (*adminuser.UpdateUserResult, error)
	UpdateUserRoles(ctx context.Context, input adminuser.UpdateUserRolesInput) (*adminuser.UpdateUserRolesResult, error)
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

// Gates are the middleware the admin routes are mounted behind. They are passed
// in rather than built here so the composition root stays the only place that
// decides how authentication works.
//
// A struct rather than positional parameters: there are five, three of them
// interchangeable-looking gin.HandlerFuncs, and a transposed pair would compile
// into a route gated by the wrong permission.
type Gates struct {
	// RequireAuth authenticates the group. On the admin surface this is the
	// admin-scope-aware gate, not the strict internal-client one.
	RequireAuth gin.HandlerFunc
	// RequireReadScope and RequireWriteScope bound what a admin-scoped
	// token may do. They are no-ops for an internal console token, whose ceiling is
	// the role gates below.
	RequireReadScope  gin.HandlerFunc
	RequireWriteScope gin.HandlerFunc
	// RequireAdmin and RequireReader are the role gates.
	RequireAdmin  gin.HandlerFunc
	RequireReader gin.HandlerFunc
}

// RegisterRoutes mounts the admin endpoints.
//
// RequireAuth must precede every other gate: they all read the Principal that
// authentication puts in the context.
//
// Two role gates rather than one, because PRD §4.12 splits the console: a lecturer
// may read the user list and detail, everything else is admin-only. The group
// carries authentication alone and each route names the gates it needs, so a new
// route with no gate fails to gain a permission by omission — it simply has none,
// which is why every route below states both a scope and a role gate explicitly.
//
// Two independent dimensions guard these routes, and both are required. The role
// gate answers "is this user allowed to do this", reading the role from the
// database row so a demotion lands on the next request. The scope gate answers
// "was this credential granted the right to act", which only constrains a
// admin-scoped token — any client holding an admin scope may reach these
// routes on an administrator's behalf, but only within the scopes it registered
// (that scope set is itself what marks it as a delegate). Neither
// gate implies the other: an administrator's token issued to a read-only delegate
// must not perform writes, and a write-scoped token belonging to a demoted user
// must not do anything.
func RegisterRoutes(r gin.IRouter, h Handler, g Gates) {
	// Fail at boot rather than serve an ungated admin route. gin would happily mount
	// a nil handler and panic on the first request instead.
	if g.RequireAuth == nil || g.RequireReadScope == nil || g.RequireWriteScope == nil ||
		g.RequireAdmin == nil || g.RequireReader == nil {
		panic("adminhandler: every gate in Gates must be set")
	}

	admin := r.Group("/admin", g.RequireAuth)
	admin.GET("/oauth-clients", g.RequireReadScope, g.RequireAdmin, h.ListClients)
	admin.POST("/oauth-clients", g.RequireWriteScope, g.RequireAdmin, h.CreateClient)
	admin.PUT("/oauth-clients/:id", g.RequireWriteScope, g.RequireAdmin, h.UpdateClient)
	admin.DELETE("/oauth-clients/:id", g.RequireWriteScope, g.RequireAdmin, h.DeleteClient)
	admin.POST("/oauth-clients/:id/rotate-secret", g.RequireWriteScope, g.RequireAdmin, h.RotateClientSecret)

	admin.GET("/users", g.RequireReadScope, g.RequireReader, h.ListUsers)
	// The static /users/batch segment wins over the :id parameter for the exact
	// path, so a lookup of the id "batch" is served here rather than 404'd by
	// GetUser — which is what the 404-on-non-numeric rule intends anyway.
	admin.GET("/users/batch", g.RequireReadScope, g.RequireReader, h.GetUsersByIDs)
	admin.GET("/users/:id", g.RequireReadScope, g.RequireReader, h.GetUser)
	// Provisioning a member is a write on the directory: write scope, admin role.
	admin.POST("/users", g.RequireWriteScope, g.RequireAdmin, h.CreateUser)
	admin.PUT("/users", g.RequireWriteScope, g.RequireAdmin, h.UpdateUsersRole)
	admin.PUT("/users/:id", g.RequireWriteScope, g.RequireAdmin, h.UpdateUser)
	admin.DELETE("/users/:id", g.RequireWriteScope, g.RequireAdmin, h.DeleteUser)
	admin.PUT("/users/:id/restore", g.RequireWriteScope, g.RequireAdmin, h.RestoreUser)

	admin.GET("/audit-logs", g.RequireReadScope, g.RequireAdmin, h.ListAuditLogs)

	// Read-only aggregate, so the read scope: a delegate trusted to list the
	// directory is not further restrained by being refused its counts.
	admin.GET("/stats", g.RequireReadScope, g.RequireAdmin, h.Stats)
}

// AdminRole is the role permitted on the write endpoints, exported so the
// composition root cannot silently mount them behind a different one.
const AdminRole = model.UserRoleAdmin

// ReaderRoles are the roles permitted on the read-only user endpoints. Exported
// for the same reason as AdminRole: the set of roles that may read the directory
// is a contract decision, not a wiring detail.
var ReaderRoles = []model.UserRole{model.UserRoleAdmin, model.UserRoleLecturer}

// ReadScopes and WriteScopes are the delegated scopes each class of admin route
// accepts, exported for the same reason as the roles above.
//
// admin:write appears in ReadScopes because write implies read: a delegate trusted
// to modify the directory is not meaningfully restrained by being refused a read
// of it, and requiring both scopes would just make every caller request both.
var (
	ReadScopes  = []string{scope.AdminRead, scope.AdminWrite}
	WriteScopes = []string{scope.AdminWrite}
)
