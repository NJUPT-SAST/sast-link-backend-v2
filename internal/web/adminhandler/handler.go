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
	// RequireAdmin, RequireReader and RequireUserWriter are the role gates.
	// RequireUserWriter admits the roles that may write user records (the admin
	// and the manager) — the member-management half of the console, which stops
	// short of the technical surfaces (OAuth clients, audit logs) that stay
	// admin-only.
	RequireAdmin      gin.HandlerFunc
	RequireReader     gin.HandlerFunc
	RequireUserWriter gin.HandlerFunc
}

// RegisterRoutes mounts the admin endpoints.
//
// RequireAuth must precede every other gate: they all read the Principal that
// authentication puts in the context.
//
// Three role gates rather than one, because PRD §4.12 splits the console: a
// lecturer may read the user directory, a manager additionally runs member
// management (user writes and the overview stats), and the technical surfaces
// (OAuth clients, the audit log, the alumni queue) are admin-only. The read
// gates admit lecturers to the list and the detail records alike — the phone
// field rides on the caller's role inside the mapping, so the endpoint stays
// open without handing the number to roles that must not see it; the alumnus
// queue (alumnihandler) is fully admin-only, since tickets carry applicants'
// contact details. A manager writing user records is bounded one level further
// down in the service layer: it may not touch an admin's account or grant the
// admin role, so the delegation cannot re-create its own superior. Each route
// names both a scope and a role gate explicitly, so a new route with no gate
// gains no permission by omission.
//
// The two independent guards are both required. The role gate answers "is this
// user allowed" from the database row, so a demotion lands on the next request;
// the scope gate answers "was this credential granted the right to act" and only
// constrains an admin-scoped token.
func RegisterRoutes(r gin.IRouter, h Handler, g Gates) {
	// Panic at boot rather than serve an ungated admin route.
	if g.RequireAuth == nil || g.RequireReadScope == nil || g.RequireWriteScope == nil ||
		g.RequireAdmin == nil || g.RequireReader == nil || g.RequireUserWriter == nil {
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
	// path, so a lookup of the id "batch" is served here rather than 404'd by GetUser.
	// Detail records (this and :id) are readable by the same roles as the list,
	// with the phone field carried only by the roles that may see it (admin and
	// manager) inside mapUserDetail.
	admin.GET("/users/batch", g.RequireReadScope, g.RequireReader, h.GetUsersByIDs)
	admin.GET("/users/:id", g.RequireReadScope, g.RequireReader, h.GetUser)
	// POST /admin/users creates an account; it needs write scope and a role that
	// may write user records (admin or manager). A manager is bounded inside the
	// service: it cannot create or promote to admin, and cannot write an admin's
	// account — see UserWriterRoles below.
	admin.POST("/users", g.RequireWriteScope, g.RequireUserWriter, h.CreateUser)
	admin.PUT("/users", g.RequireWriteScope, g.RequireUserWriter, h.UpdateUsersRole)
	admin.PUT("/users/:id", g.RequireWriteScope, g.RequireUserWriter, h.UpdateUser)
	admin.DELETE("/users/:id", g.RequireWriteScope, g.RequireUserWriter, h.DeleteUser)
	admin.PUT("/users/:id/restore", g.RequireWriteScope, g.RequireUserWriter, h.RestoreUser)

	admin.GET("/audit-logs", g.RequireReadScope, g.RequireAdmin, h.ListAuditLogs)

	// Read-only aggregate, so the read scope; a delegate trusted to list the
	// directory is not further restrained by being refused its counts. Managers
	// get it too: the overview is the management half of the console, not a
	// technical surface.
	admin.GET("/stats", g.RequireReadScope, g.RequireUserWriter, h.Stats)
}

// AdminRole is the role permitted on the technical endpoints (OAuth client
// registry, audit log), exported so the composition root cannot silently mount
// them behind a different one.
const AdminRole = model.UserRoleAdmin

// ReaderRoles are the roles permitted on the read-only user endpoints. Exported
// for the same reason as AdminRole: the set of roles that may read the directory
// is a contract decision, not a wiring detail.
var ReaderRoles = []model.UserRole{model.UserRoleAdmin, model.UserRoleManager, model.UserRoleLecturer}

// UserWriterRoles are the roles permitted to write user records and read the
// overview stats. A manager admitted here is still bounded in the service
// layer: the admin role itself cannot be granted by, and an admin's account
// cannot be written through, a manager's request.
var UserWriterRoles = []model.UserRole{model.UserRoleAdmin, model.UserRoleManager}

// ReadScopes and WriteScopes are the delegated scopes each class of admin route
// accepts. admin:write appears in ReadScopes because write implies read.
var (
	ReadScopes  = []string{scope.AdminRead, scope.AdminWrite}
	WriteScopes = []string{scope.AdminWrite}
)
