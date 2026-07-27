// Package session implements authentication session use cases without HTTP concerns.
package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
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
	KindInvalidToken      Kind = "invalid_token"
	KindEmailFailed       Kind = "email_failed"
	KindConflict          Kind = "conflict"
	KindValidationFailed  Kind = "validation_failed"
	KindInternal          Kind = "internal"
)

// Error is a typed session service error. Kind selects the HTTP mapping and
// sentinel; Code is the business error code returned to clients.
type Error struct {
	Kind       Kind
	Code       int
	Message    string
	RetryAfter time.Duration
	Err        error
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

// Is reports whether e matches target by Kind.
func (e *Error) Is(target error) bool {
	var other *Error
	if !errors.As(target, &other) {
		return false
	}
	return e.Kind == other.Kind
}

// Sentinels for each business outcome.
var (
	ErrInvalidInput            = &Error{Kind: KindInvalidInput, Code: errcode.CodeBadRequest}
	ErrRateLimited             = &Error{Kind: KindRateLimited, Code: errcode.CodeRateLimited}
	ErrLocked                  = &Error{Kind: KindLocked, Code: errcode.CodeRateLimited}
	ErrUnknownIdentifier       = &Error{Kind: KindUnknownIdentifier, Code: errcode.CodeUnknownIdentifier}
	ErrPasswordInvalid         = &Error{Kind: KindPasswordInvalid, Code: errcode.CodePasswordInvalid}
	ErrUserDeleted             = &Error{Kind: KindUserDeleted, Code: errcode.CodeAccountDeleted}
	ErrInvalidToken            = &Error{Kind: KindInvalidToken, Code: errcode.CodeAccessTokenInvalid}
	ErrEmailFailed             = &Error{Kind: KindEmailFailed, Code: errcode.CodeEmailDeliveryFailed}
	ErrVerificationCodeWrong   = &Error{Kind: KindInvalidInput, Code: errcode.CodeVerificationCodeWrong}
	ErrVerificationCodeExpired = &Error{Kind: KindInvalidInput, Code: errcode.CodeVerificationCodeExpired}
	ErrRegisterTicketInvalid   = &Error{Kind: KindInvalidToken, Code: errcode.CodeRegisterTicketInvalid}
	ErrBindTicketInvalid       = &Error{Kind: KindInvalidToken, Code: errcode.CodeBindTicketInvalid}
	ErrEmailAlreadyRegistered  = &Error{Kind: KindConflict, Code: errcode.CodeEmailAlreadyRegistered}
	ErrStudentIDOccupied       = &Error{Kind: KindConflict, Code: errcode.CodeStudentIDOccupied}
	// ErrConflict covers a uniqueness violation whose constraint is not mapped to a
	// specific field, so the response does not misattribute the clash.
	ErrConflict             = &Error{Kind: KindConflict, Code: errcode.CodeConflict}
	ErrIdentityOccupied     = &Error{Kind: KindConflict, Code: errcode.CodeIdentityOccupied}
	ErrIdentityAlreadyBound = &Error{Kind: KindConflict, Code: errcode.CodeIdentityAlreadyBound}
	ErrIdentityLimitReached = &Error{Kind: KindConflict, Code: errcode.CodeIdentityLimitReached}
	ErrPasswordTooShort     = &Error{Kind: KindValidationFailed, Code: errcode.CodePasswordTooShort}
	ErrPasswordUnchanged    = &Error{Kind: KindValidationFailed, Code: errcode.CodePasswordUnchanged}
	ErrInternal             = &Error{Kind: KindInternal, Code: errcode.CodeInternal}
)

// newError returns a contextual error that matches its sentinel via Kind.
func newError(sentinel *Error, message string, cause error) *Error {
	return &Error{Kind: sentinel.Kind, Code: sentinel.Code, Message: message, Err: cause}
}

// withRetryAfter sets RetryAfter on a freshly-built *Error. It is a no-op for
// nil or non-*Error values.
func withRetryAfter(err error, retryAfter time.Duration) error {
	var serviceErr *Error
	if !errors.As(err, &serviceErr) {
		return err
	}
	serviceErr.RetryAfter = retryAfter
	return serviceErr
}
