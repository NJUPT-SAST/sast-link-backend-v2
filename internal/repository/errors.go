package repository

import "errors"

var (
	ErrNotFound        = errors.New("repository: not found")
	ErrInvalidArgument = errors.New("repository: invalid argument")
)
