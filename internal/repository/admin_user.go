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
// PostgreSQL cannot lock an aggregate, so two concurrent demotions could each
// read "2 admins remain" and both commit, leaving zero; every writer takes this
// one advisory lock first, so those transactions serialize. The V005 migration
// uses the same technique for the cross-table email invariant. The value is
// arbitrary; the lock is always taken as the first statement of its
// transaction, so it cannot deadlock against the email key.
const adminLockKey int64 = 0x5A5701AD

// maxOtherMailBindings mirrors the V001 check_other_mail_limit trigger: at most
// two other_mail identities per account. The repository count must agree with
// the trigger so a cap breach can be reported as a classified error instead of
// the trigger's unnamed P0001.
const maxOtherMailBindings = 2

// AdminUserFilter narrows the administrative user list. Zero values mean "no
// constraint" so an empty filter lists everyone, including soft-deleted accounts:
// the console needs to find a deleted user in order to restore it.
type AdminUserFilter struct {
	Role       *model.UserRole
	State      *model.UserState
	Department *model.Department
	StudentID  string
	// Keyword matches name, student_id, login_email, qq_number, nickname,
	// blog_url or github_url case-insensitively. phone_number joins the match
	// only when IncludePhoneColumn is set, below.
	Keyword string
	// IncludePhoneColumn admits phone_number into the keyword predicate.
	// phone_number is the one field the admin-surface tightening hides from
	// non-admin roles, and the search predicate must not leak it through
	// existence probing: the caller (the handler) sets this only for an admin
	// principal, mirroring the "admin or hidden" rule the response mapping
	// applies.
	IncludePhoneColumn bool
	// NeedsCompletion filters on V010's generated flag: true lists only accounts
	// still carrying migration debris, false only the healthy ones, nil applies
	// no filter.
	NeedsCompletion *bool
	Limit           int
	Offset          int
}

// AdminUserRow is one row of the administrative user list. Column tags are
// explicit because GORM silently discards a mismatched column name.
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
	// ProfileNeedsCompletion is V010's generated column, surfaced so the console
	// list can mark the affected accounts without a second query.
	ProfileNeedsCompletion bool      `gorm:"column:profile_needs_completion"`
	CreatedAt              time.Time `gorm:"column:created_at"`
	UpdatedAt              time.Time `gorm:"column:updated_at"`
}

// ListAdminUsers returns a filtered page of users plus the total matching count,
// counted on the same predicates outside the page window and ordered by id for
// stable offset pagination.
func (r *UserRepository) ListAdminUsers(
	ctx context.Context,
	filter AdminUserFilter,
) ([]AdminUserRow, int64, error) {
	if filter.Limit <= 0 {
		return nil, 0, fmt.Errorf("%w: limit must be positive", ErrInvalidArgument)
	}
	// Over-cap is refused rather than clamped, so a caller is never handed a
	// page whose size disagrees with its request.
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
			`"user".qq_number`, `"user".college`, `"user".major`,
			`"user".profile_needs_completion`, `"user".created_at`,
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
	// IncompleteByRole counts live accounts still flagged by V010 as needing
	// profile completion whose role is not lecturer or admin, grouped by role.
	// The frontend subtracts these from ByRole and folds them into a single
	// "未补全" bucket so an incomplete account is not double-counted.
	IncompleteByRole map[model.UserRole]int64 `json:"incomplete_by_role"`
	// IncompleteByState counts live accounts still flagged incomplete grouped by
	// state. Every non-deleted state is included: the derived state machine
	// (internal/validate) classifies in-school staff as on_sast, so a njupter-only
	// count would drop them from the console overview's "未补全" bucket. The
	// frontend subtracts these from ByState into the "未补全" bucket.
	IncompleteByState map[model.UserState]int64 `json:"incomplete_by_state"`
}

// liveUser restricts a count to non-deleted accounts, since a soft-deleted row
// still exists in the table.
func liveUser(query *gorm.DB) *gorm.DB {
	return query.Where(`"user".state <> ?`, model.UserStateDeleted)
}

// Stats returns the aggregate counts for the overview dashboard.
func (r *UserRepository) Stats(ctx context.Context) (UserStats, error) {
	var stats UserStats
	stats.ByRole = make(map[model.UserRole]int64)
	stats.ByState = make(map[model.UserState]int64)
	stats.ByDepartment = make(map[model.Department]int64)
	stats.IncompleteByRole = make(map[model.UserRole]int64)
	stats.IncompleteByState = make(map[model.UserState]int64)

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
	// IncompleteByRole: only live accounts still flagged incomplete whose role is
	// neither lecturer nor admin, grouped by role for the frontend's subtraction.
	if err := liveUser(r.database.WithContext(ctx).Model(&model.User{}).
		Where(`profile_needs_completion = true AND role NOT IN (?, ?)`,
			model.UserRoleLecturer, model.UserRoleAdmin)).
		Select(`role AS "group", COUNT(*) AS count`).Group("role").Scan(&rows).Error; err != nil {
		return stats, fmt.Errorf("count users by role (incomplete): %w", err)
	}
	for _, row := range rows {
		stats.IncompleteByRole[model.UserRole(row.Group)] = row.Count
	}

	rows = rows[:0]
	// IncompleteByState: live accounts still flagged incomplete, grouped by state.
	// The group is every non-deleted state, not just njupter: since the derived
	// state machine (internal/validate) classifies in-school lecturers and admins
	// as on_sast, a njupter-only count would silently drop live staff accounts
	// from the console overview's incomplete bucket.
	if err := liveUser(r.database.WithContext(ctx).Model(&model.User{}).
		Where(`profile_needs_completion = true`)).
		Select(`state AS "group", COUNT(*) AS count`).Group("state").Scan(&rows).Error; err != nil {
		return stats, fmt.Errorf("count users by state (incomplete): %w", err)
	}
	for _, row := range rows {
		stats.IncompleteByState[model.UserState(row.Group)] = row.Count
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

// adminUserQuery builds the shared predicates of the list and its count. The
// join is LEFT so a user with a missing profile row still appears, and is
// unconditional so the list and its count see identical row sets.
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
	if filter.NeedsCompletion != nil {
		query = query.Where(`"user".profile_needs_completion = ?`, *filter.NeedsCompletion)
	}
	if filter.Keyword != "" {
		pattern := "%" + escapeLikePattern(filter.Keyword) + "%"
		cols := `("user".name ILIKE ? ESCAPE '\' OR "user".student_id ILIKE ? ESCAPE '\'` +
			` OR "user".login_email ILIKE ? ESCAPE '\' OR "user".qq_number ILIKE ? ESCAPE '\'` +
			` OR profile.nickname ILIKE ? ESCAPE '\' OR profile.blog_url ILIKE ? ESCAPE '\'` +
			` OR profile.github_url ILIKE ? ESCAPE '\'`
		args := []any{pattern, pattern, pattern, pattern, pattern, pattern, pattern}
		if filter.IncludePhoneColumn {
			cols += ` OR "user".phone_number ILIKE ? ESCAPE '\'`
			args = append(args, pattern)
		}
		cols += `)`
		query = query.Where(cols, args...)
	}
	return query
}

// escapeLikePattern neutralizes the LIKE metacharacters in a user-supplied keyword.
func escapeLikePattern(keyword string) string {
	escaped := strings.ReplaceAll(keyword, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, "%", `\%`)
	return strings.ReplaceAll(escaped, "_", `\_`)
}

// AdminUserUpdate carries the administrative field changes for one user. A nil
// pointer means "leave unchanged". token_version and password are deliberately
// absent, so no request shape can rewrite a credential or forge a version bump.
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
	// StateAuto, when true, re-derives state from the locked row's role and
	// student_id (rule in internal/validate) and clears state_manual, instead of
	// writing a pinned value. Mutually exclusive with State: the service layer
	// refuses both present, and the repository refuses the pair defensively.
	StateAuto bool
	EmailType *model.EmailType
	// PersonalEmail, when set, additionally binds the address as an other_mail
	// identity on the account, in the same transaction. This is the fix of last
	// resort for an alumnus whose school mailbox died before they bound anything:
	// the reset flow reads an other_mail binding, so one bound address reopens the
	// account from outside. Cross-account occupancy is enforced by the V005
	// triggers and the unique indexes, so no pre-flight read is needed.
	PersonalEmail *string
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
		// A state written by hand is a pin: the derived-state paths (write-side
		// derivation, retention batch) skip the row until state_auto clears it.
		columns["state_manual"] = true
	}
	if u.EmailType != nil {
		columns["email_type"] = *u.EmailType
	}
	return columns
}

// UpdateAdminUser applies an administrative edit in one transaction.
//
// Whether the write demotes an administrator is decided from the row inside the
// transaction, not from a caller-supplied flag, so the guard cannot be bypassed
// by a stale pre-transaction read: trusting that comparison would let a demotion
// commit with no guard or revocation. A role change bumps token_version and
// revokes the user's live tokens in the same transaction, so a demoted account
// cannot keep minting access tokens from live refresh tokens.
//
// Soft-deleted accounts are excluded by predicate: closing an account is
// SoftDeleteAndRevokeSessions' job, so this path never edits one and reports it
// as ErrNotFound.
func (r *UserRepository) UpdateAdminUser(
	ctx context.Context,
	userID int64,
	update AdminUserUpdate,
	revokedAt time.Time,
) ([]model.BlacklistEntry, bool, error) {
	if userID <= 0 {
		return nil, false, fmt.Errorf("%w: user id must be positive", ErrInvalidArgument)
	}
	// email_type is derived from login_email and the V001 trigger only recomputes
	// it when login_email is in the SET list; writing it alone would store a type
	// contradicting the address.
	if update.EmailType != nil && update.LoginEmail == nil {
		return nil, false, fmt.Errorf("%w: email_type cannot be set without login_email", ErrInvalidArgument)
	}
	// Closing an account must go through SoftDeleteAndRevokeSessions, which bumps
	// token_version and revokes every session in the same transaction; accepting
	// state=is_deleted here would leave every session live.
	if update.State != nil && *update.State == model.UserStateDeleted {
		return nil, false, fmt.Errorf("%w: account close must go through SoftDeleteAndRevokeSessions", ErrInvalidArgument)
	}
	// state_auto re-derives state from the locked row; carrying a pinned state
	// alongside it would be two contradictory instructions for one column.
	if update.StateAuto && update.State != nil {
		return nil, false, fmt.Errorf("%w: state and state_auto are mutually exclusive", ErrInvalidArgument)
	}
	columns := update.columns()
	if len(columns) == 0 && update.PersonalEmail == nil && !update.StateAuto {
		return nil, false, fmt.Errorf("%w: update has no fields", ErrInvalidArgument)
	}

	var entries []model.BlacklistEntry
	sessionsRevoked := false
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		// The advisory lock is taken before the user row, matching
		// SoftDeleteAndRevokeSessions' lock order so the two write paths cannot
		// deadlock each other.
		if err := transaction.Exec("SELECT pg_advisory_xact_lock(?)", adminLockKey).Error; err != nil {
			return fmt.Errorf("lock admin guard: %w", err)
		}
		// Lock the row before reading the role it is being compared against, so the
		// decision below cannot be made against a value another writer is replacing.
		var stored model.User
		if err := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id", "role", "state", "student_id").
			Where("id = ? AND state <> ?", userID, model.UserStateDeleted).
			First(&stored).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return classifyMissingUser(transaction, userID)
			}
			return fmt.Errorf("load user for update: %w", err)
		}
		if update.StateAuto {
			// state_auto re-derives from the locked row's role and student_id, so the
			// write cannot be based on values another writer is replacing, and unpins
			// in the same statement: there is no window where the row is unpinned but
			// still carries a stale pinned value. revokedAt is the caller's clock, read
			// once at the start of the request.
			derived, derErr := validate.DeriveState(stored.Role, stored.StudentID, revokedAt)
			if derErr != nil {
				// Defensive branch: student IDs are guaranteed parseable. Refusing
				// rather than guessing keeps the pin intact for the administrator to
				// overwrite with an explicit state.
				return fmt.Errorf("%w: cannot derive state from student_id: %v", ErrInvalidArgument, derErr)
			}
			columns["state"] = derived
			columns["state_manual"] = false
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
		if len(columns) > 0 {
			result := transaction.Model(&model.User{}).
				Where("id = ? AND state <> ?", userID, model.UserStateDeleted).
				Updates(columns)
			if result.Error != nil {
				return fmt.Errorf("update admin user fields: %w", result.Error)
			}
			if result.RowsAffected == 0 {
				// Either the row is missing or it is already closed; the row was locked
				// above, so this is not a lost race.
				return classifyMissingUser(transaction, userID)
			}
		}
		if update.PersonalEmail != nil {
			// The V001 check_other_mail_limit trigger refuses a third binding with an
			// unnamed P0001 that DuplicateConstraint cannot classify, so the cap is
			// checked here, inside the same transaction that already holds the admin
			// advisory lock — the count and the insert cannot race a concurrent bind.
			var bound int64
			if err := transaction.Model(&model.Identity{}).
				Where("user_id = ? AND provider = ?", userID, model.LoginMethodOtherMail).
				Count(&bound).Error; err != nil {
				return fmt.Errorf("count bound other_mail identities: %w", err)
			}
			if bound >= maxOtherMailBindings {
				return ErrIdentityLimitExceeded
			}
			// The V005 trigger refuses an address that is someone's login email and
			// the unique index refuses one already bound as other_mail, so a collision
			// surfaces as a unique violation the service classifies by constraint name.
			identity := &model.Identity{
				UserID:     userID,
				Provider:   model.LoginMethodOtherMail,
				ProviderID: *update.PersonalEmail,
			}
			if err := transaction.Create(identity).Error; err != nil {
				return fmt.Errorf("bind admin user personal email: %w", err)
			}
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
// delivery. The steps stay in one transaction because a partial failure would
// leave live refresh tokens on a closed account.
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

// RestoreUser reopens a soft-deleted account with the derived state, clearing
// the manual pin. A pinned value is deliberately not preserved: the DELETE that
// closed the account overwrote state with is_deleted, so the former pin is
// already gone and "keep it" would invent a value that no longer exists;
// re-deriving and unpinning is the only honest restart. An administrator who
// wants the account pinned again re-PUTs state after the restore. Revoked
// tokens are deliberately not restored — the owner signs in again.
//
// The row read and the UPDATE both target state = is_deleted, and no other
// writer touches a closed row, so a plain read plus a guarded UPDATE is enough;
// the RowsAffected guard still distinguishes "missing" from "already live".
func (r *UserRepository) RestoreUser(ctx context.Context, userID int64, now time.Time) error {
	if userID <= 0 {
		return fmt.Errorf("%w: user id must be positive", ErrInvalidArgument)
	}
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		var stored model.User
		if err := transaction.Select("id", "role", "student_id").
			Where("id = ? AND state = ?", userID, model.UserStateDeleted).
			First(&stored).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				// A live account is a state conflict rather than a missing one.
				return classifyLiveUser(transaction, userID)
			}
			return fmt.Errorf("load user for restore: %w", err)
		}
		state := model.UserStateNJUPTer
		if derived, derErr := validate.DeriveState(stored.Role, stored.StudentID, now); derErr == nil {
			state = derived
		}
		// else: defensive branch (student IDs are guaranteed parseable) — leave the
		// restore open rather than deadlocking the account on an unreadable ID,
		// keeping the historic njupter fallback.
		result := transaction.Model(&model.User{}).
			Where("id = ? AND state = ?", userID, model.UserStateDeleted).
			Updates(map[string]any{"state": state, "state_manual": false})
		if result.Error != nil {
			return fmt.Errorf("restore user: %w", result.Error)
		}
		if result.RowsAffected == 0 {
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
// administrator ("active" = admin whose account is not closed). The advisory
// lock (adminLockKey) is taken before the count on every admin write so a
// writer cannot demote an admin while another is mid-count.
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
	// The refusal applies only when the target is itself an active admin;
	// otherwise this write is not what would remove the last one.
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
