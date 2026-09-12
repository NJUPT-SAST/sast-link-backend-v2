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
	ErrInternal             = &Error{Kind: KindInternal, Code: errcode.CodeInternal}
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

// Callback failure stages and reasons are fixed enums recorded in the audit
// detail. Several distinct failures share one business code (a missing code and
// a stale state are both 40000), so without them an incident review cannot tell
// a scanner sending no parameters from a replayed state or a provider rejection
// without correlating application logs.
const (
	StageRequestValidation = "request_validation"
	StageState             = "state"
	StageProvider          = "provider"
	StageIdentity          = "identity"
	StageUser              = "user"
	StageSession           = "session"
	StageUnknown           = "unknown"
)

const (
	ReasonMissingCode             = "missing_code"
	ReasonMissingState            = "missing_state"
	ReasonProviderDisabled        = "provider_disabled"
	ReasonStateNotFound           = "state_not_found"
	ReasonStateStoreFailed        = "state_store_failed"
	ReasonStateCookieMissing      = "state_cookie_missing"
	ReasonStateCookieMismatch     = "state_cookie_mismatch"
	ReasonProviderMismatch        = "provider_mismatch"
	ReasonProviderInvalidGrant    = "provider_invalid_grant"
	ReasonProviderTimeout         = "provider_timeout"
	ReasonProviderCanceled        = "provider_canceled"
	ReasonProviderUnavailable     = "provider_unavailable"
	ReasonForeignTenant           = "foreign_tenant"
	ReasonIdentityLookupFailed    = "identity_lookup_failed"
	ReasonUserLookupFailed        = "user_lookup_failed"
	ReasonUserNotFound            = "user_not_found"
	ReasonUserDeleted             = "user_deleted"
	ReasonLoginCodeStoreFailed    = "login_code_store_failed"
	ReasonRegistrationStateFailed = "registration_state_failed"
	ReasonUnknown                 = "unknown"
)

// failureTag attaches a fixed audit stage/reason (and the provider-side account
// once it is known) to a callback error, without changing its Kind or business
// code. The HTTP layer never sees these fields; they exist for the audit row.
type failureTag struct {
	Stage      string
	Reason     string
	ProviderID string
	Err        error
}

func (e *failureTag) Error() string {
	if e == nil || e.Err == nil {
		return "oauthlogin: callback failure"
	}
	return e.Err.Error()
}

func (e *failureTag) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// tagCallbackFailure wraps err with the audit stage and reason for one callback
// failure step. A nil error is returned unchanged so callers can wrap inline.
func tagCallbackFailure(stage, reason string, err error) error {
	if err == nil {
		return nil
	}
	return &failureTag{Stage: stage, Reason: reason, Err: err}
}

// tagCallbackFailureWithProvider is tagCallbackFailure once the provider
// exchange succeeded, so the audit row names the provider-side account.
func tagCallbackFailureWithProvider(stage, reason, providerID string, err error) error {
	if err == nil {
		return nil
	}
	return &failureTag{Stage: stage, Reason: reason, ProviderID: providerID, Err: err}
}

// failureDetail extracts the audit stage/reason/provider id, defaulting to the
// unknown stage and reason so the fields are always present on a failed
// callback row.
func failureDetail(err error) (stage, reason, providerID string) {
	var tag *failureTag
	if errors.As(err, &tag) {
		return tag.Stage, tag.Reason, tag.ProviderID
	}
	return StageUnknown, ReasonUnknown, ""
}
