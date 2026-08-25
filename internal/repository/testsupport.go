package repository

import (
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

// NewUniqueViolationForTest builds the driver error a unique-index collision
// produces.
//
// A regular file rather than an export_test one because the callers are service
// packages: an export_test helper is compiled only into this package's own tests
// and would be invisible to them. Service tests need it so they exercise their
// real constraint-name classification — a hand-rolled stub error would route
// around DuplicateConstraint and leave the mapping that runs in production
// unverified.
func NewUniqueViolationForTest(constraint string) error {
	return &pgconn.PgError{
		Code:           pgerrcode.UniqueViolation,
		ConstraintName: constraint,
	}
}
