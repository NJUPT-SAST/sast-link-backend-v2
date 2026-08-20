package adminuser

import (
	"context"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// Audit resources and actions for this service. PRD §4.13 groups administrative
// edits under one audit trail; the action names distinguish which one ran.
const (
	auditResourceUser = "user"

	actionUpdateUser  = "admin_user_update"
	actionDeleteUser  = "admin_user_delete"
	actionRestoreUser = "admin_user_restore"
)

// UserRepository reads and writes user accounts for the console.
type UserRepository interface {
	ListAdminUsers(ctx context.Context, filter repository.AdminUserFilter) ([]repository.AdminUserRow, int64, error)
	// FindByID resolves a user with its profile and identities, regardless of state:
	// the console must be able to inspect a closed account in order to restore it.
	FindByID(ctx context.Context, userID int64) (*model.User, error)
	// FindByIDs resolves many users with their profile and identities, regardless
	// of state, in unspecified order; ids that match nothing are silently absent.
	FindByIDs(ctx context.Context, ids []int64) ([]model.User, error)
	// FindAuthUserByID returns the scalar columns without the Profile/Identities
	// preloads, for edit paths that only act on the account row itself.
	FindAuthUserByID(ctx context.Context, userID int64) (*model.User, error)
	// UpdateAdminUser decides for itself whether the edit demotes an administrator,
	// from the row locked inside its transaction. It takes no flag for that: a caller's
	// comparison is against a read from before the transaction, and acting on it let a
	// demotion commit unguarded and unrevoked.
	UpdateAdminUser(
		ctx context.Context,
		userID int64,
		update repository.AdminUserUpdate,
		revokedAt time.Time,
	) (entries []model.BlacklistEntry, sessionsRevoked bool, err error)
	SoftDeleteAndRevokeSessions(
		ctx context.Context,
		userID int64,
		revokedAt time.Time,
	) ([]model.BlacklistEntry, error)
	RestoreUser(ctx context.Context, userID int64) error
	// Stats returns the aggregate account counts for the console overview.
	Stats(ctx context.Context) (repository.UserStats, error)
	// NamesByIDs returns display names for the given user ids.
	NamesByIDs(ctx context.Context, ids []int64) (map[int64]string, error)
}

// AuditLogRepository records and queries audit events.
type AuditLogRepository interface {
	Create(ctx context.Context, entry *model.AuditLog) error
	List(ctx context.Context, filter repository.AuditLogFilter) ([]model.AuditLog, int64, error)
}

// TokenBlacklist invalidates the auth-state cache entries for revoked access
// tokens. Revocation is authoritative in PostgreSQL; this clears the short-TTL
// cache so the middleware's next request re-checks the database immediately.
type TokenBlacklist interface {
	DeleteAuthStates(ctx context.Context, jtis []string) error
}

// DeviceStore clears a user's device records when an administrative action
// (role demotion, state change, account close) revokes every session. The
// method mirrors the session service's DeviceStore port so the same Redis
// adapter satisfies both (the packages must not import each other, PRD §6.1).
type DeviceStore interface {
	RemoveAllDevices(ctx context.Context, userID int64) error
}

// ListUsersInput is a filtered, paged user query. Page and PageSize are validated
// and clamped here rather than in the handler, so every caller gets the same
// bounds.
type ListUsersInput struct {
	Page       int
	PageSize   int
	Role       string
	State      string
	Department string
	StudentID  string
	Keyword    string
	// NeedsCompletion filters on the migration-debris flag. Nil applies no
	// filter, so the default list is unchanged; a pointer makes "show me the
	// backlog" and "show me the healthy accounts" both expressible, which a bare
	// bool could not do.
	NeedsCompletion *bool
}

// ListUsersResult is one page of the user list.
type ListUsersResult struct {
	Users    []UserListItem
	Total    int64
	Page     int
	PageSize int
}

// UserListItem is one user as reported to the console.
type UserListItem struct {
	ID          int64
	Name        string
	StudentID   string
	LoginEmail  string
	Role        string
	State       string
	EmailType   string
	PhoneNumber string
	QQNumber    string
	College     string
	Major       string
	Department  *string
	// ProfileNeedsCompletion marks an account still carrying values imported from
	// the previous database. IncompleteFields names them so the console can show
	// what is missing without re-deriving the rule.
	ProfileNeedsCompletion bool
	IncompleteFields       []string
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// UpdateUserInput is a partial administrative edit. A nil field is left
// unchanged. There is no PasswordHash or TokenVersion field: a credential rewrite
// is not an edit, and the version counter is the repository's to bump.
//
// Batch marks an edit issued by the batch role-update endpoint; it changes
// nothing about the write, only the audit detail, which records "batch": true so
// the console can tell a mass promotion from an individual edit.
type UpdateUserInput struct {
	UserID      int64
	Name        *string
	PhoneNumber *string
	QQNumber    *string
	StudentID   *string
	Major       *string
	College     *string
	LoginEmail  *string
	Role        *string
	State       *string
	EmailType   *string
	Batch       bool
	// AdminUserID is the authenticated administrator, for the audit trail and for
	// the self-demotion guard.
	AdminUserID int64
	// ActorClientID is the azp of the token that authorized this call. Empty means a
	// console session, which the audit records as ConsoleClientID.
	ActorClientID string
	ClientIP      string
	UserAgent     string
}

// UpdateUserResult reports what the update did.
type UpdateUserResult struct {
	// ChangedFields lists the applied field names in contract order, for the audit
	// detail and so the console can confirm what landed.
	ChangedFields []string
	// RevokedSessions is true when the role changed and every session of the user
	// was cut as a result.
	RevokedSessions bool
}

// TargetUserInput identifies the subject of a delete or restore.
type TargetUserInput struct {
	UserID      int64
	AdminUserID int64
	// ActorClientID is the azp of the token that authorized this call. Empty means a
	// console session, which the audit records as ConsoleClientID.
	ActorClientID string
	ClientIP      string
	UserAgent     string
}

// GetUsersByIDsInput is a batch user-detail read. IDs must be non-empty and
// within the documented batch cap; duplicates are collapsed in the service.
type GetUsersByIDsInput struct {
	IDs []int64
}

// UpdateUserRolesInput is a batch role change. IDs must be non-empty and within
// the documented batch cap; Role must be one of the four user roles. Each id is
// updated independently and reported per item, so one failure does not abort
// the rest.
type UpdateUserRolesInput struct {
	IDs  []int64
	Role string
	// AdminUserID is the authenticated administrator, for the audit trail and for
	// the self-demotion guard (an administrator cannot change their own role
	// through the batch either).
	AdminUserID int64
	// ActorClientID is the azp of the token that authorized this call. Empty means a
	// console session, which the audit records as ConsoleClientID.
	ActorClientID string
	ClientIP      string
	UserAgent     string
}

// UpdateUserRolesResult is the per-item outcome of a batch role change. The HTTP
// response is 200 whenever the request itself was well formed; an item-level
// failure is data, not transport, so the caller can retry or alert on it.
type UpdateUserRolesResult struct {
	Results []RoleUpdateResult
}

// RoleUpdateResult is one id's outcome. Success carries the requested role so
// the caller can confirm what landed; failure carries a literal reason, never
// an echo of submitted values.
type RoleUpdateResult struct {
	ID      int64
	Success bool
	Role    string
	Reason  string
}

// ListAuditLogsInput is a filtered, paged audit query.
type ListAuditLogsInput struct {
	Page     int
	PageSize int
	UserID   *int64
	Action   string
	Resource string
	Success  *bool
	// ActorClientID narrows the page to one acting OAuth client.
	ActorClientID string
	StartTime     *time.Time
	EndTime       *time.Time
}

// ListAuditLogsResult is one page of the audit log.
type ListAuditLogsResult struct {
	Logs     []AuditLogItem
	Total    int64
	Page     int
	PageSize int
}

// AuditLogItem is one audit entry as reported to the console.
type AuditLogItem struct {
	ID         int64
	UserID     *int64
	UserName   *string
	Action     string
	Resource   string
	ResourceID *string
	Detail     model.JSONB
	ClientIP   *string
	UserAgent  *string
	Success    bool
	ErrCode    *int
	// ActorClientID is the OAuth client whose credential authorized the action. Null
	// means none did: an unauthenticated flow, a background worker, or a row predating
	// the column.
	ActorClientID *string
	CreatedAt     time.Time
}

// UserDetail is a full user record for the console. Written out field by field
// rather than returning model.User, which carries the password hash: a type with
// no such field cannot leak it however the model changes later.
type UserDetail struct {
	ID          int64
	Name        string
	LoginEmail  string
	Role        string
	State       string
	EmailType   string
	PhoneNumber string
	QQNumber    string
	StudentID   string
	College     string
	Major       string
	// See UserListItem.
	ProfileNeedsCompletion bool
	IncompleteFields       []string
	Profile                *ProfileDetail
	Identities             []IdentityDetail
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// ProfileDetail is the display-card half of a user record.
type ProfileDetail struct {
	Nickname   *string
	Department *string
	Intro      *string
	Email      *string
	Avatar     *string
	BlogURL    *string
	GitHubURL  *string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// IdentityDetail is one third-party binding. The stored provider access and refresh
// tokens are absent: the console displays bindings, it does not hand out the
// credentials behind them.
//
// identity_data is absent for the same reason — it is the provider's whole user
// object, carrying mobile and email addresses, and these endpoints are readable by
// lecturers as well as administrators.
type IdentityDetail struct {
	ID             int64
	Provider       string
	ProviderID     string
	TokenExpiresAt *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
