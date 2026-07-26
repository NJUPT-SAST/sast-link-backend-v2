package repository

import "errors"

var (
	ErrNotFound        = errors.New("repository: not found")
	ErrInvalidArgument = errors.New("repository: invalid argument")
	// ErrLimitExceeded reports that a bounded-cardinality insert would exceed its cap.
	ErrLimitExceeded = errors.New("repository: limit exceeded")
)
