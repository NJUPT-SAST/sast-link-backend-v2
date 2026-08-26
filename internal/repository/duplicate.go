package repository

import (
	"errors"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

// DuplicateConstraint returns the name of the unique constraint a write
// violated, or "" when err is not a unique violation. The constraint name is the
// only reliable discriminator because PostgreSQL leaves ColumnName empty for
// index violations. It lives in the repository layer because four services need
// the same classification; each still maps the name onto its own error wording.
func DuplicateConstraint(err error) string {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != pgerrcode.UniqueViolation {
		return ""
	}
	return pgErr.ConstraintName
}
