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
	KindNotFound          Kind = "not_found"
	KindInternal          Kind = "internal"
	// KindObjectUploadFailed reports that an object-storage upload or review
	// failed (errcode 50002). Distinct from KindInternal so the HTTP layer maps
	// the documented code without a code-override case.
	KindObjectUploadFailed Kind = "object_upload_failed"
	// KindDependencyUnavailable is for fail-closed dependencies (verification
	// codes, tickets) that cannot be validated when their Redis store is down.
	// It maps to HTTP 503 so a Redis outage does not surface as a server bug.
	KindDependencyUnavailable Kind = "dependency_unavailable"
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
	// ErrIdentityNotFound covers both a missing binding and one owned by another
	// user. They deliberately share a code so an authenticated caller cannot probe
	// which identity IDs exist outside their own account.
	ErrIdentityNotFound = &Error{Kind: KindNotFound, Code: errcode.CodeNotFound}
	ErrUserNotFound     = &Error{Kind: KindNotFound, Code: errcode.CodeUserNotFound}
	// ErrLastLoginMethod rejects unbinding the caller's only remaining login
	// method, which would lock them out of their own account.
	ErrLastLoginMethod = &Error{Kind: KindValidationFailed, Code: errcode.CodeValidationFailed}
	// ErrValidationFailed is the generic 42200 for business rules that do not
	// have a dedicated code, such as a rejected content review.
	ErrValidationFailed = &Error{Kind: KindValidationFailed, Code: errcode.CodeValidationFailed}
	// ErrObjectUploadFailed reports a failed object-storage upload or content
	// review. The review failure is deliberately fail-closed: an image that was
	// not reviewed must not be served as cleared.
	ErrObjectUploadFailed = &Error{Kind: KindObjectUploadFailed, Code: errcode.CodeObjectUploadFailed}
	// ErrDatabase reports a persistence failure with the documented 50003 code.
	ErrDatabase = &Error{Kind: KindInternal, Code: errcode.CodeDatabaseFailed}
	ErrInternal = &Error{Kind: KindInternal, Code: errcode.CodeInternal}
	// ErrDependencyUnavailable reports that a fail-closed Redis-backed store
	// (verification codes, register/bind tickets) is unreachable. Per PRD §6.0
	// these flows must reject the request so the user can retry, not mask the
	// outage as an internal 500.
	ErrDependencyUnavailable = &Error{Kind: KindDependencyUnavailable, Code: errcode.CodeDependencyUnavailable}
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
