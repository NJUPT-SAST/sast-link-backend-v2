// Package oauthlogin implements third-party OAuth login, binding and the
// registration hand-off, without HTTP concerns.
package oauthlogin

import (
	"errors"
	"fmt"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
)

// Kind identifies a typed failure for HTTP-layer mapping; it mirrors
// session.Kind rather than importing it.
type Kind string

const (
	KindInvalidInput Kind = "invalid_input"
	KindRateLimited  Kind = "rate_limited"
	KindInvalidState Kind = "invalid_state"
	KindInvalidToken Kind = "invalid_token"
	KindUserDeleted  Kind = "user_deleted"
	KindForbidden    Kind = "forbidden"
	KindConflict     Kind = "conflict"
	KindNotFound     Kind = "not_found"
	KindInternal     Kind = "internal"
	// KindProviderUnavailable marks a failed outbound call to GitHub or Lark,
	// mapping to HTTP 502.
	KindProviderUnavailable Kind = "provider_unavailable"
	// KindDependencyUnavailable flags the fail-closed Redis state this flow owns
	// (oauth_state, registration_state, login_code): a missing value cannot be
	// treated as valid, and the flow is rejected with HTTP 503 rather than masked
	// as an internal error.
	KindDependencyUnavailable Kind = "dependency_unavailable"
)

// Error is a typed service error. Kind selects the HTTP mapping; Code is the
// business error code returned to clients.
type Error struct {
	Kind    Kind
	Code    int
	Message string
	// Display marks Message as written for the end user, so the HTTP layer
	// surfaces it instead of the generic per-Kind string.
	//
	// Off by default: most messages name an internal step or a broken dependency,
	// which is a log line, not something to hand a browser. Only outcomes the user
	// can act on differently from the Kind default set it.
	Display bool
	// RetryAfter carries the limiter's remaining window so the HTTP layer can
	// emit a Retry-After header.
	RetryAfter time.Duration
	Err        error
}

func (e *Error) Error() string {
	if e == nil {
		return "oauthlogin: <nil>"
	}
	if e.Err == nil {
		return fmt.Sprintf("oauthlogin: %s", e.Message)
	}
	return fmt.Sprintf("oauthlogin: %s: %v", e.Message, e.Err)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Is reports whether e matches target by Kind, so callers and tests can compare
// against a sentinel without caring about the message.
func (e *Error) Is(target error) bool {
	var other *Error
	if !errors.As(target, &other) {
		return false
	}
	return e.Kind == other.Kind
}

// Sentinels for each business outcome.
var (
	ErrInvalidInput = &Error{Kind: KindInvalidInput, Code: errcode.CodeBadRequest}
	// ErrRateLimited reports that a per-IP endpoint cap was exceeded.
	ErrRateLimited = &Error{Kind: KindRateLimited, Code: errcode.CodeRateLimited}
	// ErrStateInvalid covers a missing, expired or already-consumed OAuth state;
	// all three are one outcome: restart the login.
	ErrStateInvalid = &Error{Kind: KindInvalidState, Code: errcode.CodeBadRequest}
	// ErrLoginCodeInvalid covers a login_code that is unknown, expired or spent.
	ErrLoginCodeInvalid = &Error{Kind: KindInvalidToken, Code: errcode.CodeLoginCodeInvalid}
	// Registration-state failures are raised by the session service, which owns
	// POST /auth/register; this package only writes the parked state and needs no
	// sentinel for them.
	ErrUserDeleted = &Error{Kind: KindUserDeleted, Code: errcode.CodeAccountDeleted}
	// ErrForeignTenant rejects a Lark account outside the SAST enterprise.
	ErrForeignTenant = &Error{Kind: KindForbidden, Code: errcode.CodeLarkTenantRequired}
	// ErrIdentityOccupied means the third-party account is already bound to a
	// different user.
	ErrIdentityOccupied = &Error{Kind: KindConflict, Code: errcode.CodeIdentityOccupied}
	// ErrIdentityAlreadyBound means the caller already holds a binding of this
	// provider. V001 caps github and lark at one row per user.
	ErrIdentityAlreadyBound = &Error{Kind: KindConflict, Code: errcode.CodeIdentityAlreadyBound}
	ErrUserNotFound         = &Error{Kind: KindNotFound, Code: errcode.CodeUserNotFound}
	// ErrPasswordInvalid reports a wrong current password during step-up
	// re-authentication. KindInvalidToken surfaces it as 401, like every other
	// failed credential check; the code is what audit and tests match on.
	ErrPasswordInvalid = &Error{Kind: KindInvalidToken, Code: errcode.CodePasswordInvalid}
	ErrInternal        = &Error{Kind: KindInternal, Code: errcode.CodeInternal}
	// ErrProviderUnavailable reports that GitHub or Lark could not be reached or
	// answered in a shape this service does not understand.
	ErrProviderUnavailable = &Error{Kind: KindProviderUnavailable, Code: errcode.CodeDependencyUnavailable}
	// ErrDependencyUnavailable reports that the fail-closed Redis state backing
	// this flow is unreachable.
	ErrDependencyUnavailable = &Error{Kind: KindDependencyUnavailable, Code: errcode.CodeDependencyUnavailable}
)

// newError returns a contextual error that matches its sentinel via Kind. The
// message stays internal; the HTTP layer answers with the per-Kind default.
func newError(sentinel *Error, message string, cause error) *Error {
	return &Error{Kind: sentinel.Kind, Code: sentinel.Code, Message: message, Err: cause}
}

// newDisplayError is newError for a message the user is meant to read, for an
// outcome its Kind's default string would describe wrongly.
func newDisplayError(sentinel *Error, message string, cause error) *Error {
	err := newError(sentinel, message, cause)
	err.Display = true
	return err
}

// withRetryAfter sets RetryAfter on a freshly built *Error. It is a no-op for
// nil or non-*Error values.
func withRetryAfter(err error, retryAfter time.Duration) error {
	var serviceErr *Error
	if !errors.As(err, &serviceErr) {
		return err
	}
	serviceErr.RetryAfter = retryAfter
	return serviceErr
}
