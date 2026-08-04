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
}

// AuditLogRepository records and queries audit events.
type AuditLogRepository interface {
	Create(ctx context.Context, entry *model.AuditLog) error
	List(ctx context.Context, filter repository.AuditLogFilter) ([]model.AuditLog, int64, error)
}

// TokenBlacklist is the fast-reject cache for revoked access tokens.
type TokenBlacklist interface {
	BlacklistJTIBatch(ctx context.Context, entries map[string]time.Duration) error
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
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// UpdateUserInput is a partial administrative edit. A nil field is left
// unchanged. There is no PasswordHash or TokenVersion field: a credential rewrite
// is not an edit, and the version counter is the repository's to bump.
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
	// AdminUserID is the authenticated administrator, for the audit trail and for
	// the self-demotion guard.
	AdminUserID int64
	ClientIP    string
	UserAgent   string
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
	ClientIP    string
	UserAgent   string
}

// ListAuditLogsInput is a filtered, paged audit query.
type ListAuditLogsInput struct {
	Page      int
	PageSize  int
	UserID    *int64
	Action    string
	Resource  string
	Success   *bool
	StartTime *time.Time
	EndTime   *time.Time
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
	Action     string
	Resource   string
	ResourceID *string
	Detail     model.JSONB
	ClientIP   *string
	UserAgent  *string
	Success    bool
	ErrCode    *int
	CreatedAt  time.Time
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
	Profile     *ProfileDetail
	Identities  []IdentityDetail
	CreatedAt   time.Time
	UpdatedAt   time.Time
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
