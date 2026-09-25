// Package badge implements the personal-badge feature without HTTP concerns:
// opt-in enable, idempotent disable and status. The public SVG rendering and
// the HTTP surface live with this package's handler siblings.
package badge

import (
	"errors"
	"fmt"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
)

// Kind identifies a typed failure for HTTP-layer mapping; it mirrors the
// session and oauthlogin Kind types rather than importing them.
type Kind string

const (
	KindInvalidInput     Kind = "invalid_input"
	KindValidationFailed Kind = "validation_failed"
	KindNotFound         Kind = "not_found"
	KindConflict         Kind = "conflict"
	KindRateLimited      Kind = "rate_limited"
	KindInternal         Kind = "internal"
)

// Error is a typed service error. Kind selects the HTTP mapping; Code is the
// business error code returned to clients.
type Error struct {
	Kind    Kind
	Code    int
	Message string
	// Display marks Message as written for the end user, so the HTTP layer
	// surfaces it instead of the generic per-Kind string.
	Display bool
	// RetryAfter carries the limiter's remaining window so the HTTP layer can
	// emit a Retry-After header.
	RetryAfter time.Duration
	Err        error
}

func (e *Error) Error() string {
	if e == nil {
		return "badge: <nil>"
	}
	if e.Err == nil {
		return fmt.Sprintf("badge: %s", e.Message)
	}
	return fmt.Sprintf("badge: %s: %v", e.Message, e.Err)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Is reports whether e matches target by Kind, so callers and tests can
// compare against a sentinel without caring about the message.
func (e *Error) Is(target error) bool {
	var other *Error
	if !errors.As(target, &other) {
		return false
	}
	return e.Kind == other.Kind
}

// Sentinels for each business outcome.
var (
	// ErrUserNotFound covers an enable or status call whose subject does not
	// exist (or is deleted — FindPublicCardByUserID folds both into one).
	ErrUserNotFound = &Error{Kind: KindNotFound, Code: errcode.CodeUserNotFound}
	// ErrAlreadyEnabled is an enable call on an account that already holds a
	// badge. The client's remedy is to show the existing badge, not to retry.
	ErrAlreadyEnabled = &Error{Kind: KindConflict, Code: errcode.CodeBadgeAlreadyEnabled}
	// ErrNicknameMissing is an enable call on a profile with no nickname: the
	// nickname is the badge's identity anchor, so the enable is refused with a
	// pointer at the profile edit instead of rendering a nameless card.
	ErrNicknameMissing = &Error{Kind: KindValidationFailed, Code: errcode.CodeBadgeNicknameMissing, Display: true}
	// ErrRateLimited reports that the per-user badge toggle cap was exceeded.
	ErrRateLimited = &Error{Kind: KindRateLimited, Code: errcode.CodeRateLimited}
	ErrInternal    = &Error{Kind: KindInternal, Code: errcode.CodeInternal}
)

// newError returns a contextual error that matches its sentinel via Kind. The
// message stays internal; the HTTP layer answers with the per-Kind default.
// Display carries over from the sentinel: an outcome written for the end user
// stays user-facing no matter which call site raises it.
func newError(sentinel *Error, message string, cause error) *Error {
	return &Error{Kind: sentinel.Kind, Code: sentinel.Code, Message: message, Display: sentinel.Display, Err: cause}
}

// withRetryAfter attaches the limiter's remaining window so the HTTP layer can
// emit a Retry-After header.
func withRetryAfter(err *Error, retryAfter time.Duration) *Error {
	err.RetryAfter = retryAfter
	return err
}
