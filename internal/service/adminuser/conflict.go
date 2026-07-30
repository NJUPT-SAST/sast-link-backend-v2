package adminuser

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

// PostgreSQL's unique-index names for the "user" table. It carries two unique
// constraints, so a bare SQLSTATE 23505 check cannot tell which column collided —
// reporting "邮箱已被注册" for a student-ID clash sends the administrator to the
// wrong field. Mirrors the session package's constant block.
const (
	userLoginEmailConstraint = "user_login_email_key"
	userStudentIDConstraint  = "user_student_id_key"
	// V005 raises this from a trigger with SQLSTATE unique_violation, so it arrives
	// here like any other duplicate. It fires when a login email would take an
	// address already bound as an other_mail identity — including on another account.
	userLoginEmailIsIdentityConstraint = "ck_user_login_email_not_identity"
)

// mapUniqueViolation names the colliding column, falling back to internalMessage
// for anything that is not a duplicate.
//
// login_email and student_id are unique across all accounts, so an administrative
// edit can lose a race against a registration or another edit. An unmapped
// constraint is logged rather than guessed at: reporting the wrong field is worse
// than reporting a generic conflict, and the log is what makes a new constraint
// visible.
func (s Service) mapUniqueViolation(ctx context.Context, err error, internalMessage string) error {
	switch constraint := duplicateConstraint(err); constraint {
	case userLoginEmailConstraint, userLoginEmailIsIdentityConstraint:
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
// err is not a unique violation. PostgreSQL leaves ColumnName empty for index
// violations, so the constraint name is the only reliable discriminator.
func duplicateConstraint(err error) string {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != pgerrcode.UniqueViolation {
		return ""
	}
	return pgErr.ConstraintName
}
