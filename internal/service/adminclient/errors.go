// Package adminclient implements the administrative OAuth client registry use
// cases without HTTP concerns.
//
// Kept separate from package oauth: that package implements the OAuth 2.1 and OIDC
// protocol flows, where the caller is a registered client. These are management
// operations whose caller is a human administrator. Folding them together would
// give one service both the protocol logic and the console's write paths, and the
// authorization models are unrelated — client_secret versus an admin role.
package adminclient

import (
	"errors"
	"fmt"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
)

// Kind identifies a typed failure for HTTP-layer mapping.
type Kind string

const (
	KindInvalidInput Kind = "invalid_input"
	KindNotFound     Kind = "not_found"
	KindConflict     Kind = "conflict"
	// KindProtected is an attempt to change the built-in client in a way that would
	// break authentication for everyone. HTTP 403: the request is understood and
	// well formed, the target is simply not the caller's to change.
	KindProtected Kind = "protected"
	KindInternal  Kind = "internal"
)

// Error is a typed admin-client service error.
type Error struct {
	Kind    Kind
	Code    int
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return "adminclient: <nil>"
	}
	if e.Err == nil {
		return fmt.Sprintf("adminclient: %s", e.Message)
	}
	return fmt.Sprintf("adminclient: %s: %v", e.Message, e.Err)
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
	ErrInvalidInput = &Error{Kind: KindInvalidInput, Code: errcode.CodeBadRequest}
	ErrNotFound     = &Error{Kind: KindNotFound, Code: errcode.CodeClientNotFound}
	ErrConflict     = &Error{Kind: KindConflict, Code: errcode.CodeConflict}
	// ErrProtectedClient refuses a change to the built-in client that would break
	// the internal session flow. Distinct from ErrInvalidInput because the input is
	// well formed — it is the target that is off limits — and the console needs to
	// tell the two apart to explain why.
	ErrProtectedClient = &Error{Kind: KindProtected, Code: errcode.CodeForbidden}
	ErrInternal        = &Error{Kind: KindInternal, Code: errcode.CodeInternal}
)

// newError builds a typed error carrying sentinel's Kind and Code.
//
// The message is always a literal at the call site and never interpolates caller
// input: descriptions reach the client verbatim, so echoing a submitted value back
// would make this a reflection point. The cause travels in Err for the logs only.
func newError(sentinel *Error, message string, cause error) error {
	return &Error{Kind: sentinel.Kind, Code: sentinel.Code, Message: message, Err: cause}
}
