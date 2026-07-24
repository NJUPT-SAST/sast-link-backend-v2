// Package session implements authentication session use cases without HTTP concerns.
package session

import (
	"errors"
	"fmt"
)

// Kind identifies a typed session service failure for HTTP-layer mapping.
type Kind string

const (
	KindInvalidInput      Kind = "invalid_input"
	KindRateLimited       Kind = "rate_limited"
	KindLocked            Kind = "locked"
	KindUnknownIdentifier Kind = "unknown_identifier"
	KindPasswordInvalid   Kind = "password_invalid"
	KindUserDeleted       Kind = "user_deleted"
	KindInvalidClient     Kind = "invalid_client"
	KindInvalidToken      Kind = "invalid_token"
	KindInternal          Kind = "internal"
)

const (
	CodeInvalidInput      = 40000
	CodeInvalidToken      = 40102
	CodePasswordInvalid   = 40105
	CodeUnknownIdentifier = 40106
	CodeUserDeleted       = 40301
	CodeRateLimited       = 42900
	CodeInternal          = 50000
)

// Error is a typed service error. Code is the business code expected by HTTP handlers.
type Error struct {
	Kind    Kind
	Code    int
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return "session: <nil>"
	}
	if e.Err == nil {
		return fmt.Sprintf("session: %s", e.Message)
	}
	return fmt.Sprintf("session: %s: %v", e.Message, e.Err)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *Error) Is(target error) bool {
	var other *Error
	if !errors.As(target, &other) {
		return false
	}
	return e.Kind == other.Kind
}

var (
	ErrInvalidInput      = &Error{Kind: KindInvalidInput}
	ErrRateLimited       = &Error{Kind: KindRateLimited}
	ErrLocked            = &Error{Kind: KindLocked}
	ErrUnknownIdentifier = &Error{Kind: KindUnknownIdentifier}
	ErrPasswordInvalid   = &Error{Kind: KindPasswordInvalid}
	ErrUserDeleted       = &Error{Kind: KindUserDeleted}
	ErrInvalidClient     = &Error{Kind: KindInvalidClient}
	ErrInvalidToken      = &Error{Kind: KindInvalidToken}
	ErrInternal          = &Error{Kind: KindInternal}
)

func serviceError(kind Kind, code int, message string, err error) *Error {
	return &Error{Kind: kind, Code: code, Message: message, Err: err}
}
