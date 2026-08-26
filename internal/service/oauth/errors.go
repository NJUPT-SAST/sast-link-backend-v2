// Package oauth implements the OAuth 2.1 authorization server and OIDC Provider
// use cases without HTTP concerns.
package oauth

import (
	"errors"
	"fmt"
	"time"
)

// RFC 6749 §4.1.2.1 / §5.2 and RFC 6750 §3.1 error codes.
const (
	ErrorInvalidRequest       = "invalid_request"
	ErrorUnauthorizedClient   = "unauthorized_client"
	ErrorAccessDenied         = "access_denied"
	ErrorUnsupportedResponse  = "unsupported_response_type"
	ErrorInvalidScope         = "invalid_scope"
	ErrorServerError          = "server_error"
	ErrorTemporarilyUnavail   = "temporarily_unavailable"
	ErrorInvalidClient        = "invalid_client"
	ErrorInvalidGrant         = "invalid_grant"
	ErrorUnsupportedGrantType = "unsupported_grant_type"
	ErrorInvalidToken         = "invalid_token"
)

// Kind classifies an OAuth failure for HTTP-layer mapping. The OAuth error code
// alone is not enough: RFC 6749 §5.2 puts invalid_client on 401 and every other
// token error on 400, and the authorize endpoint additionally has to decide
// whether an error may be redirected to the client at all.
type Kind string

const (
	// KindInvalidRequest is a malformed or incomplete request. HTTP 400.
	KindInvalidRequest Kind = "invalid_request"
	// KindInvalidClient is a failed client authentication. HTTP 401, and RFC 6749
	// §5.2 requires a WWW-Authenticate header when the client used one.
	KindInvalidClient Kind = "invalid_client"
	// KindInvalidGrant is a bad, expired, replayed or mismatched grant. HTTP 400.
	KindInvalidGrant Kind = "invalid_grant"
	// KindAccessDenied is the user refusing consent. Redirectable.
	KindAccessDenied Kind = "access_denied"
	// KindInvalidToken is a rejected bearer token on UserInfo. HTTP 401 with an
	// RFC 6750 WWW-Authenticate challenge.
	KindInvalidToken Kind = "invalid_token"
	// KindRateLimited throttles a caller. HTTP 429; not an RFC 6749 code, so it
	// maps onto temporarily_unavailable on the wire.
	KindRateLimited Kind = "rate_limited"
	// KindDependencyUnavailable is a fail-closed Redis store being unreachable.
	// HTTP 503; a request whose parameters cannot be retrieved cannot be treated as
	// consented.
	KindDependencyUnavailable Kind = "dependency_unavailable"
	// KindInternal is a server-side fault. HTTP 500.
	KindInternal Kind = "internal"
)

// Error is a typed OAuth service error.
//
// Redirectable is the security-relevant field: RFC 6749 §4.1.2.1 forbids
// redirecting an error to an unvalidated redirect_uri, or the authorize endpoint
// becomes an open redirector. Only errors raised after client_id and redirect_uri
// both check out may travel back to the client; everything else stays on the
// consent page.
type Error struct {
	Kind Kind
	// Code is the RFC error code placed in the `error` field.
	Code string
	// Description becomes error_description. It must stay free of anything the
	// client did not already know: this string is handed to the caller verbatim.
	Description string
	// Redirectable reports whether this error may be delivered to the client's
	// redirect_uri instead of the consent page.
	Redirectable bool
	RetryAfter   time.Duration
	Err          error
}

func (e *Error) Error() string {
	if e == nil {
		return "oauth: <nil>"
	}
	if e.Err == nil {
		return fmt.Sprintf("oauth: %s: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("oauth: %s: %s: %v", e.Code, e.Description, e.Err)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Is reports whether e matches target by Kind, mirroring session.Error so
// callers can compare against the sentinels below.
func (e *Error) Is(target error) bool {
	var other *Error
	if !errors.As(target, &other) {
		return false
	}
	return e.Kind == other.Kind
}

// Sentinels for each business outcome. Redirectable is set per call site, not
// here: the same invalid_request is redirectable once the client and
// redirect_uri have been validated and must not be before.
var (
	ErrInvalidRequest        = &Error{Kind: KindInvalidRequest, Code: ErrorInvalidRequest}
	ErrUnsupportedResponse   = &Error{Kind: KindInvalidRequest, Code: ErrorUnsupportedResponse}
	ErrInvalidScope          = &Error{Kind: KindInvalidRequest, Code: ErrorInvalidScope}
	ErrUnauthorizedClient    = &Error{Kind: KindInvalidRequest, Code: ErrorUnauthorizedClient}
	ErrInvalidClient         = &Error{Kind: KindInvalidClient, Code: ErrorInvalidClient}
	ErrInvalidGrant          = &Error{Kind: KindInvalidGrant, Code: ErrorInvalidGrant}
	ErrUnsupportedGrantType  = &Error{Kind: KindInvalidRequest, Code: ErrorUnsupportedGrantType}
	ErrAccessDenied          = &Error{Kind: KindAccessDenied, Code: ErrorAccessDenied}
	ErrInvalidToken          = &Error{Kind: KindInvalidToken, Code: ErrorInvalidToken}
	ErrRateLimited           = &Error{Kind: KindRateLimited, Code: ErrorTemporarilyUnavail}
	ErrDependencyUnavailable = &Error{Kind: KindDependencyUnavailable, Code: ErrorTemporarilyUnavail}
	ErrInternal              = &Error{Kind: KindInternal, Code: ErrorServerError}
)

// newError returns a non-redirectable error matching its sentinel.
func newError(sentinel *Error, description string, cause error) *Error {
	return &Error{
		Kind:        sentinel.Kind,
		Code:        sentinel.Code,
		Description: description,
		Err:         cause,
	}
}

// redirectableError returns an error the authorize endpoint may deliver to the
// client's already-validated redirect_uri.
func redirectableError(sentinel *Error, description string, cause error) *Error {
	err := newError(sentinel, description, cause)
	err.Redirectable = true
	return err
}

// withRetryAfter sets RetryAfter on a freshly built *Error.
func withRetryAfter(err error, retryAfter time.Duration) error {
	var oauthErr *Error
	if !errors.As(err, &oauthErr) {
		return err
	}
	oauthErr.RetryAfter = retryAfter
	return oauthErr
}
