package repository

import (
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

// NewUniqueViolationForTest builds the driver error a unique-index collision
// produces. It is a regular file rather than an export_test one so service
// packages can exercise their real constraint-name classification.
func NewUniqueViolationForTest(constraint string) error {
	return &pgconn.PgError{
		Code:           pgerrcode.UniqueViolation,
		ConstraintName: constraint,
	}
}
