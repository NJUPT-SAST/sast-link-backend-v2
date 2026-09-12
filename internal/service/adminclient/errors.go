// Package adminclient implements the administrative OAuth client registry use
// cases without HTTP concerns.
//
// Kept separate from package oauth: these are management operations whose caller
// is a human administrator, where oauth's caller is a registered client.
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
	// KindStateConflict is an update whose target registration changed between the
	// read the guards were evaluated against and the write. HTTP 409: the request is
	// well formed, the row simply is not the one that was decided on, and the caller
	// re-reads before retrying.
	KindStateConflict Kind = "state_conflict"
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
	// ErrConcurrentUpdate reports a registration that moved between the read the
	// guards used and the write. It reuses CodeConflict rather than taking a code of
	// its own: 409 is already what a client handles as "retry after re-reading", and
	// the message names the retry. Distinct from ErrConflict, whose message is
	// "OAuth 客户端已存在" and whose outcome is not retryable.
	ErrConcurrentUpdate = &Error{Kind: KindStateConflict, Code: errcode.CodeConflict, Message: "OAuth 客户端配置已被其他操作修改，请刷新后重试"}
	// ErrProtectedClient refuses a change to the built-in client that would break
	// the internal session flow; distinct from ErrInvalidInput because the target
	// is off limits, not the input.
	ErrProtectedClient = &Error{Kind: KindProtected, Code: errcode.CodeForbidden}
	ErrInternal        = &Error{Kind: KindInternal, Code: errcode.CodeInternal}
)

// newError builds a typed error carrying sentinel's Kind and Code. The message is a
// literal at the call site, never caller input; the cause travels in Err for the logs.
func newError(sentinel *Error, message string, cause error) error {
	return &Error{Kind: sentinel.Kind, Code: sentinel.Code, Message: message, Err: cause}
}
