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
	// KindLoginFailed is what a failed sign-in answers with, unknown identifier
	// and wrong password alike (audit-fix #7): the wire must not distinguish the
	// two, or a login attempt becomes a registered-email oracle. The audit trail
	// keeps the distinction via the failure reason.
	KindLoginFailed      Kind = "login_failed"
	KindUserDeleted      Kind = "user_deleted"
	KindInvalidToken     Kind = "invalid_token"
	KindEmailFailed      Kind = "email_failed"
	KindConflict         Kind = "conflict"
	KindValidationFailed Kind = "validation_failed"
	KindNotFound         Kind = "not_found"
	KindInternal         Kind = "internal"
	// KindObjectUploadFailed reports that an object-storage upload or review
	// failed (errcode 50002), distinct from KindInternal.
	KindObjectUploadFailed Kind = "object_upload_failed"
	// KindDependencyUnavailable flags fail-closed dependencies (verification
	// codes, tickets) whose Redis store is unreachable, mapping to HTTP 503 so an
	// outage does not surface as a server bug.
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
	ErrInvalidInput      = &Error{Kind: KindInvalidInput, Code: errcode.CodeBadRequest}
	ErrRateLimited       = &Error{Kind: KindRateLimited, Code: errcode.CodeRateLimited}
	ErrLocked            = &Error{Kind: KindLocked, Code: errcode.CodeRateLimited}
	ErrUnknownIdentifier = &Error{Kind: KindUnknownIdentifier, Code: errcode.CodeUnknownIdentifier}
	ErrPasswordInvalid   = &Error{Kind: KindPasswordInvalid, Code: errcode.CodePasswordInvalid}
	// ErrLoginFailed is the single code a failed sign-in returns whether the
	// identifier is unknown or the password wrong, so neither leg leaks whether
	// the address is registered (audit-fix #7).
	ErrLoginFailed  = &Error{Kind: KindLoginFailed, Code: errcode.CodePasswordInvalid}
	ErrUserDeleted  = &Error{Kind: KindUserDeleted, Code: errcode.CodeAccountDeleted}
	ErrInvalidToken = &Error{Kind: KindInvalidToken, Code: errcode.CodeAccessTokenInvalid}
	// ErrConcurrentRefresh reports a benign concurrent refresh within the 30s
	// grace window: a sibling rotation already cut this token but preserved the
	// family. It stays an invalid-token outcome for the client, but distinct so
	// the session handler does not clear the cookie that now holds the winner's token.
	ErrConcurrentRefresh       = &Error{Kind: KindInvalidToken, Code: errcode.CodeConcurrentRefresh}
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
	// user; they share a code so a caller cannot probe identity IDs outside their
	// own account.
	ErrIdentityNotFound = &Error{Kind: KindNotFound, Code: errcode.CodeNotFound}
	// ErrDeviceNotFound covers both a missing device and one owned by another
	// user: the ownership gate already ran, so anything past it reports
	// identically without leaking existence.
	ErrDeviceNotFound = &Error{Kind: KindNotFound, Code: errcode.CodeNotFound}
	ErrUserNotFound   = &Error{Kind: KindNotFound, Code: errcode.CodeUserNotFound}
	// ErrLastLoginMethod rejects unbinding the caller's only remaining login
	// method, which would lock them out of their own account.
	ErrLastLoginMethod = &Error{Kind: KindValidationFailed, Code: errcode.CodeValidationFailed}
	// ErrAvatarRejected reports that the content review refused the uploaded
	// avatar. Distinct from the generic validation code so the client can tell a
	// policy rejection from a malformed request.
	ErrAvatarRejected = &Error{Kind: KindValidationFailed, Code: errcode.CodeAvatarRejected}
	// ErrObjectUploadFailed reports a failed object-storage upload. The content
	// review has its own fail-closed path (ErrDependencyUnavailable): an image
	// that was not reviewed must not be served as cleared.
	ErrObjectUploadFailed = &Error{Kind: KindObjectUploadFailed, Code: errcode.CodeObjectUploadFailed}
	// ErrDatabase reports a persistence failure with the documented 50003 code.
	ErrDatabase = &Error{Kind: KindInternal, Code: errcode.CodeDatabaseFailed}
	ErrInternal = &Error{Kind: KindInternal, Code: errcode.CodeInternal}
	// ErrDependencyUnavailable reports that a fail-closed Redis-backed store
	// (verification codes, register/bind tickets) is unreachable; the flow
	// rejects so the user can retry, rather than masking the outage as an
	// internal 500.
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
