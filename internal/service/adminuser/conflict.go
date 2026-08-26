package adminuser

import (
	"context"
	"log/slog"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// PostgreSQL's unique-index names for the "user" table. It carries two unique
// constraints, so a bare SQLSTATE 23505 check cannot tell which column collided —
// reporting "邮箱已被注册" for a student-ID clash sends the administrator to the
// wrong field. Mirrors the session package's constant block.
const (
	userLoginEmailConstraint = "user_login_email_key"
	userStudentIDConstraint  = "user_student_id_key"
	// V005 raises both triggers as SQLSTATE unique_violation.
	// ck_user_login_email_not_identity fires when a login email would take an
	// address already bound as other_mail; the mirror forbids an identity insert
	// claiming an address already used as a login email. This is the race an admin
	// provisioning can hit when its personal-email pre-check loses to a concurrent
	// registration.
	userLoginEmailIsIdentityConstraint        = "ck_user_login_email_not_identity"
	identityProviderIDNotLoginEmailConstraint = "ck_identities_provider_id_not_login_email"
	// identities' own uniqueness guard. The console pre-checks with
	// ExistsAsEmailAnywhere, so this only lands after a race; it still needs a name,
	// not a logged "unmapped" 500.
	identityProviderProviderIDConstraint = "uq_identities_provider_provider_id"
)

// mapUniqueViolation names the colliding column, falling back to internalMessage
// for anything that is not a duplicate. An unmapped constraint is logged rather
// than guessed at: reporting the wrong field is worse than a generic conflict.
func (s Service) mapUniqueViolation(ctx context.Context, err error, internalMessage string) error {
	switch constraint := duplicateConstraint(err); constraint {
	case userLoginEmailConstraint, userLoginEmailIsIdentityConstraint,
		identityProviderIDNotLoginEmailConstraint, identityProviderProviderIDConstraint:
		return newError(ErrEmailOccupied, "邮箱已被占用", err)
	case userStudentIDConstraint:
		return newError(ErrStudentIDOccupied, "学号已被占用", err)
	case "":
		return newError(ErrInternal, internalMessage, err)
	default:
		slog.ErrorContext(ctx, "unmapped unique violation on admin user write",
			"constraint", constraint)
		return newError(ErrConflict, "用户资料与现有账号冲突", err)
	}
}

// duplicateConstraint returns the violated unique constraint's name, or "" when
// err is not a unique violation. Thin wrapper over the repository helper; the
// mapping onto this service's error type stays local, because the same collision
// reads differently to an administrator than to a user binding their own account.
func duplicateConstraint(err error) string {
	return repository.DuplicateConstraint(err)
}
