// Package oauthlogin implements third-party OAuth login, binding and the
// registration hand-off, without HTTP concerns.
package oauthlogin

import (
	"errors"
	"fmt"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
)

// Kind identifies a typed failure for HTTP-layer mapping. It mirrors
// session.Kind rather than importing it: the two packages map onto different
// subsets of outcomes, and aliasing would let a session-only Kind leak into a
// mapping table that has no arm for it.
type Kind string

const (
	KindInvalidInput Kind = "invalid_input"
	KindInvalidState Kind = "invalid_state"
	KindInvalidToken Kind = "invalid_token"
	KindUserDeleted  Kind = "user_deleted"
	KindForbidden    Kind = "forbidden"
	KindConflict     Kind = "conflict"
	KindNotFound     Kind = "not_found"
	KindInternal     Kind = "internal"
	// KindProviderUnavailable is for a failed outbound call to GitHub or Lark.
	// It maps to HTTP 502: the request was well formed and this service is
	// healthy, but an upstream it depends on is not.
	KindProviderUnavailable Kind = "provider_unavailable"
	// KindDependencyUnavailable is for the fail-closed Redis state this flow
	// owns (oauth_state, registration_state, login_code). Per PRD §6.0 a missing
	// value cannot be treated as valid, so the flow is rejected with HTTP 503
	// rather than masked as an internal error.
	KindDependencyUnavailable Kind = "dependency_unavailable"
)

// Error is a typed service error. Kind selects the HTTP mapping; Code is the
// business error code returned to clients.
type Error struct {
	Kind    Kind
	Code    int
	Message string
	Err     error
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
	// ErrStateInvalid covers a missing, expired or already-consumed OAuth state.
	// All three are one outcome for the user: restart the login.
	ErrStateInvalid = &Error{Kind: KindInvalidState, Code: errcode.CodeBadRequest}
	// ErrLoginCodeInvalid covers a login_code that is unknown, expired or spent.
	ErrLoginCodeInvalid = &Error{Kind: KindInvalidToken, Code: errcode.CodeLoginCodeInvalid}
	// Registration-state failures are raised by the session service, which owns
	// POST /auth/register and has its own sentinel for them; this package only
	// writes the parked state, so it needs no equivalent here.
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
	ErrInternal             = &Error{Kind: KindInternal, Code: errcode.CodeInternal}
	// ErrProviderUnavailable reports that GitHub or Lark could not be reached or
	// answered in a shape this service does not understand.
	ErrProviderUnavailable = &Error{Kind: KindProviderUnavailable, Code: errcode.CodeDependencyUnavailable}
	// ErrDependencyUnavailable reports that the fail-closed Redis state backing
	// this flow is unreachable.
	ErrDependencyUnavailable = &Error{Kind: KindDependencyUnavailable, Code: errcode.CodeDependencyUnavailable}
)

// newError returns a contextual error that matches its sentinel via Kind.
func newError(sentinel *Error, message string, cause error) *Error {
	return &Error{Kind: sentinel.Kind, Code: sentinel.Code, Message: message, Err: cause}
}
