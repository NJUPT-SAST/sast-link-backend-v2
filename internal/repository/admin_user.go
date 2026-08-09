package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// adminLockKey serializes the writes that must observe an accurate count of
// active administrators.
//
// PostgreSQL cannot lock an aggregate: SELECT count(*) ... FOR UPDATE is not
// valid, and locking the rows the count read does not stop a concurrent
// transaction from demoting a different row. Two simultaneous demotions would
// each read "2 admins remain" and both commit, leaving zero. Every writer takes
// this one advisory lock first, so those transactions serialize. The V005
// migration uses the same technique for the cross-table email invariant.
//
// The value is arbitrary. It shares the single-argument bigint advisory keyspace
// with V005, whose keys are hashtextextended over an email address and so could in
// principle land on this constant — nothing rules that out. A collision would only
// make an email write and an admin write wait for each other, never corrupt either,
// since both are transaction-scoped mutexes. Deadlock is separately impossible:
// this lock is only ever taken as the first statement of its transaction, so it
// cannot be acquired after an email key.
const adminLockKey int64 = 0x5A5701AD

// AdminUserFilter narrows the administrative user list. Zero values mean "no
// constraint" so an empty filter lists everyone, including soft-deleted accounts:
// the console needs to find a deleted user in order to restore it.
type AdminUserFilter struct {
	Role       *model.UserRole
	State      *model.UserState
	Department *model.Department
	StudentID  string
	// Keyword matches name, student_id or login_email case-insensitively.
	Keyword string
	Limit   int
	Offset  int
}

// AdminUserRow is one row of the administrative user list.
//
// Column tags are explicit on every field for the reason documented on
// PublicCard: GORM's naming strategy derives names this query does not select,
// and a mismatch is discarded silently rather than reported.
type AdminUserRow struct {
	ID          int64             `gorm:"column:id"`
	Name        string            `gorm:"column:name"`
	StudentID   string            `gorm:"column:student_id"`
	LoginEmail  string            `gorm:"column:login_email"`
	Role        model.UserRole    `gorm:"column:role"`
	State       model.UserState   `gorm:"column:state"`
	EmailType   model.EmailType   `gorm:"column:email_type"`
	PhoneNumber string            `gorm:"column:phone_number"`
	QQNumber    string            `gorm:"column:qq_number"`
	College     model.College     `gorm:"column:college"`
	Major       string            `gorm:"column:major"`
	Department  *model.Department `gorm:"column:department"`
	CreatedAt   time.Time         `gorm:"column:created_at"`
	UpdatedAt   time.Time         `gorm:"column:updated_at"`
}

// ListAdminUsers returns a filtered page of users plus the total matching count.
//
// The count runs against the same predicates without the page window, so a
// caller paging through a filtered set sees a total consistent with what it can
// actually reach. Ordering is by id so the pages of an offset scan do not
// overlap; created_at alone is not unique enough to be a stable sort key.
func (r *UserRepository) ListAdminUsers(
	ctx context.Context,
	filter AdminUserFilter,
) ([]AdminUserRow, int64, error) {
	if filter.Limit <= 0 {
		return nil, 0, fmt.Errorf("%w: limit must be positive", ErrInvalidArgument)
	}
	// The result slice is sized from Limit before any row is read, so an unbounded limit
	// reserves memory for rows that may not exist — 50 million AdminUserRows is
	// gigabytes for a query that can return nothing. Refusing rather than clamping: this
	// method is exported, and a caller asking for a page this large has misunderstood
	// the contract, which serves at most MaxPageSize per page everywhere. Silently
	// returning a differently sized page would hide that.
	if filter.Limit > validate.MaxPageSize {
		return nil, 0, fmt.Errorf("%w: limit must not exceed %d",
			ErrInvalidArgument, validate.MaxPageSize)
	}
	if filter.Offset < 0 {
		return nil, 0, fmt.Errorf("%w: offset must not be negative", ErrInvalidArgument)
	}

	var total int64
	if err := r.adminUserQuery(ctx, filter).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count admin users: %w", err)
	}
	if total == 0 {
		return []AdminUserRow{}, 0, nil
	}

	rows := make([]AdminUserRow, 0, filter.Limit)
	err := r.adminUserQuery(ctx, filter).
		Select(`"user".id`, `"user".name`, `"user".student_id`, `"user".login_email`,
			`"user".role`, `"user".state`, `"user".email_type`, `"user".phone_number`,
			`"user".qq_number`, `"user".college`, `"user".major`, `"user".created_at`,
			`"user".updated_at`, "profile.department").
		Order(`"user".id`).
		Limit(filter.Limit).
		Offset(filter.Offset).
		Find(&rows).Error
	if err != nil {
		return nil, 0, fmt.Errorf("list admin users: %w", err)
	}
	return rows, total, nil
}

// UserStats aggregates the account dimensions the console overview shows.
//
// Soft deletion here is a state bit (is_deleted), not a deleted_at column, so the
// "live account" dimensions must exclude it explicitly. Total, ByRole and
// ByDepartment / NoDepartment count only accounts whose state is not is_deleted;
// ByState counts every state, is_deleted included, so the console can show how
// many accounts were deleted without inflating the usable-account totals.
type UserStats struct {
	Total        int64                      `json:"total"`
	ByRole       map[model.UserRole]int64   `json:"by_role"`
	ByState      map[model.UserState]int64  `json:"by_state"`
	ByDepartment map[model.Department]int64 `json:"by_department"`
	// NoDepartment counts users whose profile has no department (freshman /
	// njupter before recruitment, or a missing profile row).
	NoDepartment int64 `json:"no_department"`
}

// liveUser predicates every non-deleted-account count: a soft-deleted row still
// exists in the table, so an unfiltered COUNT would inflate the totals the
// console reads as "usable accounts".
func liveUser(query *gorm.DB) *gorm.DB {
	return query.Where(`"user".state <> ?`, model.UserStateDeleted)
}

// Stats returns the aggregate counts for the overview dashboard.
func (r *UserRepository) Stats(ctx context.Context) (UserStats, error) {
	var stats UserStats
	stats.ByRole = make(map[model.UserRole]int64)
	stats.ByState = make(map[model.UserState]int64)
	stats.ByDepartment = make(map[model.Department]int64)

	if err := liveUser(r.database.WithContext(ctx).Model(&model.User{})).
		Count(&stats.Total).Error; err != nil {
		return stats, fmt.Errorf("count users: %w", err)
	}

	type groupRow struct {
		Group string
		Count int64
	}
	rows := make([]groupRow, 0, 8)

	if err := liveUser(r.database.WithContext(ctx).Model(&model.User{})).
		Select(`role AS "group", COUNT(*) AS count`).Group("role").Scan(&rows).Error; err != nil {
		return stats, fmt.Errorf("count users by role: %w", err)
	}
	for _, row := range rows {
		stats.ByRole[model.UserRole(row.Group)] = row.Count
	}

	rows = rows[:0]
	// ByState deliberately keeps every state, is_deleted included, so the deleted
	// count stays visible as its own bucket rather than vanishing from the console.
	if err := r.database.WithContext(ctx).Model(&model.User{}).
		Select(`state AS "group", COUNT(*) AS count`).Group("state").Scan(&rows).Error; err != nil {
		return stats, fmt.Errorf("count users by state: %w", err)
	}
	for _, row := range rows {
		stats.ByState[model.UserState(row.Group)] = row.Count
	}

	rows = rows[:0]
	if err := liveUser(r.database.WithContext(ctx).Model(&model.User{})).
		Joins(`LEFT JOIN profile ON profile.user_id = "user".id`).
		Select(`profile.department AS "group", COUNT(*) AS count`).
		Group("profile.department").Scan(&rows).Error; err != nil {
		return stats, fmt.Errorf("count users by department: %w", err)
	}
	for _, row := range rows {
		if row.Group == "" {
			stats.NoDepartment = row.Count
			continue
		}
		stats.ByDepartment[model.Department(row.Group)] = row.Count
	}

	return stats, nil
}

// adminUserQuery builds the shared predicates of the list and its count.
//
// The join is LEFT rather than INNER so a user whose profile row is missing still
// appears, with a null department. An INNER join would hide exactly the accounts
// an administrator is most likely looking for. It is unconditional so that both
// halves of the pair see identical row sets.
func (r *UserRepository) adminUserQuery(ctx context.Context, filter AdminUserFilter) *gorm.DB {
	query := r.database.WithContext(ctx).
		Model(&model.User{}).
		Joins(`LEFT JOIN profile ON profile.user_id = "user".id`)
	if filter.Role != nil {
		query = query.Where(`"user".role = ?`, *filter.Role)
	}
	if filter.State != nil {
		query = query.Where(`"user".state = ?`, *filter.State)
	}
	if filter.Department != nil {
		query = query.Where("profile.department = ?", *filter.Department)
	}
	if filter.StudentID != "" {
		query = query.Where(`"user".student_id = ?`, filter.StudentID)
	}
	if filter.Keyword != "" {
		pattern := "%" + escapeLikePattern(filter.Keyword) + "%"
		query = query.Where(
			`("user".name ILIKE ? ESCAPE '\' OR "user".student_id ILIKE ? ESCAPE '\'`+
				` OR "user".login_email ILIKE ? ESCAPE '\')`,
			pattern, pattern, pattern)
	}
	return query
}

// escapeLikePattern neutralizes the LIKE metacharacters in a user-supplied
// keyword. Without it, a keyword of "%" matches every row and "_" matches any
// single character, so the search silently means something other than what was
// typed. The backslash is escaped first, otherwise it would double-escape the
// escapes added afterwards.
func escapeLikePattern(keyword string) string {
	escaped := strings.ReplaceAll(keyword, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, "%", `\%`)
	return strings.ReplaceAll(escaped, "_", `\_`)
}

// AdminUserUpdate carries the administrative field changes for one user. A nil
// pointer means "leave unchanged". Unlike ProfileUpdate this type does reach the
// identity and permission columns, which is the whole point of the admin console;
// token_version and password are still absent, so no request shape can rewrite a
// credential or forge a version bump through this path.
type AdminUserUpdate struct {
	Name        *string
	PhoneNumber *string
	QQNumber    *string
	StudentID   *string
	Major       *string
	College     *model.College
	LoginEmail  *string
	Role        *model.UserRole
	State       *model.UserState
	EmailType   *model.EmailType
}

// columns returns the "user" table assignments, empty when untouched.
func (u AdminUserUpdate) columns() map[string]any {
	columns := make(map[string]any, 10)
	assign(columns, "name", u.Name)
	assign(columns, "phone_number", u.PhoneNumber)
	assign(columns, "qq_number", u.QQNumber)
	assign(columns, "student_id", u.StudentID)
	assign(columns, "major", u.Major)
	assign(columns, "login_email", u.LoginEmail)
	if u.College != nil {
		columns["college"] = *u.College
	}
	if u.Role != nil {
		columns["role"] = *u.Role
	}
	if u.State != nil {
		columns["state"] = *u.State
	}
	if u.EmailType != nil {
		columns["email_type"] = *u.EmailType
	}
	return columns
}

// UpdateAdminUser applies an administrative edit in one transaction.
//
// Whether the write demotes an administrator, and therefore whether it needs the
// last-admin guard and a session revocation, is decided here from the row as it
// exists inside the transaction. It is deliberately not a caller-supplied flag: a
// caller compares against a read taken before the transaction opened, so by the time
// the write lands the stored role may have changed underneath it. Since the update
// writes the role column whenever one was submitted, trusting that comparison let a
// demotion commit with no guard, no token_version bump and no revocation — the
// combination that empties the administrator set and leaves a demoted account still
// able to mint access tokens.
//
// A role change increments token_version and revokes every live token of the user in
// this same transaction rather than after it. Splitting them would leave a window
// where a demoted account still holds refresh tokens able to mint access tokens,
// since the refresh flow does not compare token_version.
//
// Soft-deleted accounts are excluded by predicate: closing an account is
// DELETE's job and reopening it is restore's, so this path never edits one and
// reports it as ErrNotFound.
func (r *UserRepository) UpdateAdminUser(
	ctx context.Context,
	userID int64,
	update AdminUserUpdate,
	revokedAt time.Time,
) ([]model.BlacklistEntry, bool, error) {
	if userID <= 0 {
		return nil, false, fmt.Errorf("%w: user id must be positive", ErrInvalidArgument)
	}
	// email_type is derived from login_email, and the V001 trigger only recomputes it
	// when login_email is in the SET list. Writing it alone would therefore store a type
	// contradicting the address, with nothing downstream to correct it. Refusing here
	// keeps that unrepresentable at the layer that owns the column rather than resting
	// on every caller validating it first.
	if update.EmailType != nil && update.LoginEmail == nil {
		return nil, false, fmt.Errorf("%w: email_type cannot be set without login_email", ErrInvalidArgument)
	}
	columns := update.columns()
	if len(columns) == 0 {
		return nil, false, fmt.Errorf("%w: update has no fields", ErrInvalidArgument)
	}

	var entries []model.BlacklistEntry
	sessionsRevoked := false
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		// Lock the row before reading the role it is being compared against, so the
		// decision below cannot be made against a value another writer is replacing.
		var stored model.User
		if err := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id", "role", "state").
			Where("id = ? AND state <> ?", userID, model.UserStateDeleted).
			First(&stored).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return classifyMissingUser(transaction, userID)
			}
			return fmt.Errorf("load user for update: %w", err)
		}
		demotesAdmin := update.Role != nil &&
			*update.Role != model.UserRoleAdmin && stored.Role == model.UserRoleAdmin
		roleChanged := update.Role != nil && *update.Role != stored.Role
		if demotesAdmin {
			if err := ensureAnotherAdminRemains(transaction, userID); err != nil {
				return err
			}
		}
		if roleChanged {
			columns["token_version"] = gorm.Expr("token_version + 1")
		}
		result := transaction.Model(&model.User{}).
			Where("id = ? AND state <> ?", userID, model.UserStateDeleted).
			Updates(columns)
		if result.Error != nil {
			return fmt.Errorf("update admin user fields: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return ErrNotFound
		}
		if !roleChanged {
			return nil
		}
		sessionsRevoked = true
		revoked, revokeErr := revokeAllByUserInTransaction(transaction, userID, revokedAt)
		if revokeErr != nil {
			return revokeErr
		}
		entries = revoked
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrLastAdmin) {
			return nil, false, err
		}
		return nil, false, fmt.Errorf("update admin user: %w", err)
	}
	return entries, sessionsRevoked, nil
}

// SoftDeleteAndRevokeSessions closes an account and cuts every session it holds
// in one transaction, returning the access-token entries still needing blacklist
// delivery.
//
// The three steps are inseparable for the reason given on UpdateAdminUser: the
// state flag alone stops new logins and is checked by the auth middleware, but a
// partial failure would leave live refresh tokens on a closed account.
func (r *UserRepository) SoftDeleteAndRevokeSessions(
	ctx context.Context,
	userID int64,
	revokedAt time.Time,
) ([]model.BlacklistEntry, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("%w: user id must be positive", ErrInvalidArgument)
	}
	var entries []model.BlacklistEntry
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := ensureAnotherAdminRemains(transaction, userID); err != nil {
			return err
		}
		result := transaction.Model(&model.User{}).
			Where("id = ? AND state <> ?", userID, model.UserStateDeleted).
			Updates(map[string]any{
				"state":         model.UserStateDeleted,
				"token_version": gorm.Expr("token_version + 1"),
			})
		if result.Error != nil {
			return fmt.Errorf("soft delete user: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			// Either the row is missing or it is already closed. Tell those apart so the
			// console can report "already deleted" instead of "no such user".
			return classifyMissingUser(transaction, userID)
		}
		revoked, revokeErr := revokeAllByUserInTransaction(transaction, userID, revokedAt)
		if revokeErr != nil {
			return revokeErr
		}
		entries = revoked
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrStateConflict) || errors.Is(err, ErrLastAdmin) {
			return nil, err
		}
		return nil, fmt.Errorf("soft delete and revoke sessions: %w", err)
	}
	return entries, nil
}

// RestoreUser reopens a soft-deleted account at the njupter state.
//
// Revoked tokens are deliberately not restored: they were cut when the account
// closed and the owner signs in again. PRD §4.9 also states the restored state is
// always njupter — the previous state is not remembered, so an on_sast member
// comes back as a njupter and an administrator re-promotes them.
func (r *UserRepository) RestoreUser(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return fmt.Errorf("%w: user id must be positive", ErrInvalidArgument)
	}
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		result := transaction.Model(&model.User{}).
			Where("id = ? AND state = ?", userID, model.UserStateDeleted).
			Update("state", model.UserStateNJUPTer)
		if result.Error != nil {
			return fmt.Errorf("restore user: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			// A live account is a state conflict, not a missing one; reporting 404 for a
			// user the console just listed would look like the record had vanished.
			return classifyLiveUser(transaction, userID)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrStateConflict) {
			return err
		}
		return fmt.Errorf("restore user: %w", err)
	}
	return nil
}

// ensureAnotherAdminRemains refuses a write that would remove the last active
// administrator, where "active" means an admin whose account is not closed.
//
// The advisory lock is taken before the count and is why this is correct under
// concurrency; see adminLockKey. It is taken even when the target is not an
// admin, which costs one lock per admin write but keeps every writer on the same
// serialization point — a writer that skipped the lock could demote the second
// admin while a locked writer was busy demoting the first.
func ensureAnotherAdminRemains(transaction *gorm.DB, userID int64) error {
	if err := transaction.Exec("SELECT pg_advisory_xact_lock(?)", adminLockKey).Error; err != nil {
		return fmt.Errorf("lock admin guard: %w", err)
	}
	var remaining int64
	if err := transaction.Model(&model.User{}).
		Where("role = ? AND state <> ? AND id <> ?",
			model.UserRoleAdmin, model.UserStateDeleted, userID).
		Count(&remaining).Error; err != nil {
		return fmt.Errorf("count remaining admins: %w", err)
	}
	if remaining > 0 {
		return nil
	}
	// The target is only blocking if it is itself an active admin: when it is not,
	// there was no administrator to begin with and this write is not what removed
	// one, so refusing it would make the console unusable rather than safer.
	var isActiveAdmin int64
	if err := transaction.Model(&model.User{}).
		Where("id = ? AND role = ? AND state <> ?",
			userID, model.UserRoleAdmin, model.UserStateDeleted).
		Count(&isActiveAdmin).Error; err != nil {
		return fmt.Errorf("check target admin state: %w", err)
	}
	if isActiveAdmin > 0 {
		return ErrLastAdmin
	}
	return nil
}

// classifyMissingUser explains a zero-row write whose predicate excluded deleted
// accounts.
func classifyMissingUser(transaction *gorm.DB, userID int64) error {
	var count int64
	if err := transaction.Model(&model.User{}).Where("id = ?", userID).Count(&count).Error; err != nil {
		return fmt.Errorf("classify missing user: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return ErrStateConflict
}

// classifyLiveUser explains a zero-row write whose predicate required a deleted
// account.
func classifyLiveUser(transaction *gorm.DB, userID int64) error {
	var count int64
	if err := transaction.Model(&model.User{}).Where("id = ?", userID).Count(&count).Error; err != nil {
		return fmt.Errorf("classify live user: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return ErrStateConflict
}
