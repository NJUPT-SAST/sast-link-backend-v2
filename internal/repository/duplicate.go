package repository

import (
	"errors"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

// DuplicateConstraint returns the name of the unique constraint a write
// violated, or "" when err is not a unique violation.
//
// The constraint name is the only reliable discriminator: PostgreSQL leaves
// ColumnName empty for index violations, so a bare SQLSTATE 23505 check cannot
// tell a colliding login email from a colliding student ID. Reporting the wrong
// one sends the caller to fix a field that is not the problem.
//
// This lives in the repository layer because four services need the same
// classification — the console's user writes, self-service identity binding,
// third-party OAuth binding, and the alumni account-request flow — and it is
// pure inspection of a driver error, not policy. Each service still maps the returned name onto its own error type and
// wording: the same collision means "邮箱已被占用" to an administrator and
// something else entirely to a user binding their own GitHub account.
func DuplicateConstraint(err error) string {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != pgerrcode.UniqueViolation {
		return ""
	}
	return pgErr.ConstraintName
}
