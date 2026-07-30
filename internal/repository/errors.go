package repository

import "errors"

var (
	ErrNotFound        = errors.New("repository: not found")
	ErrInvalidArgument = errors.New("repository: invalid argument")
	// ErrLimitExceeded reports that a bounded-cardinality insert would exceed its cap.
	ErrLimitExceeded = errors.New("repository: limit exceeded")
	// ErrStateConflict reports that the row exists but its current state does not
	// allow the requested transition, e.g. restoring an account that is not deleted.
	// Distinct from ErrNotFound so the caller can say which of the two happened
	// instead of reporting a live account as missing.
	ErrStateConflict = errors.New("repository: state conflict")
	// ErrLastAdmin reports that the write would leave the system with no active
	// administrator. Enforced in the database rather than by the service because the
	// check is a count over other rows, so only the writing transaction can hold it.
	ErrLastAdmin = errors.New("repository: last active admin")
)
