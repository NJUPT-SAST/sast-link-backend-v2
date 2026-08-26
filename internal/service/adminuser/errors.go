// Package adminuser implements the administrative user-management and audit-log
// use cases without HTTP concerns.
//
// Kept separate from package adminclient: that package's audit resource and 404
// semantics are fixed to OAuth clients, and the dependency sets do not overlap.
package adminuser

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
)

// Kind identifies a typed failure for HTTP-layer mapping.
type Kind string

const (
	KindInvalidInput Kind = "invalid_input"
	KindNotFound     Kind = "not_found"
	KindConflict     Kind = "conflict"
	// KindStateConflict is a request whose target exists but is in a state that does
	// not allow the operation, e.g. restoring an account that was never closed. HTTP
	// 422: the input is well formed and the resource exists, the transition is what
	// is refused.
	KindStateConflict Kind = "state_conflict"
	// KindProtected is an attempt to remove the caller's own administrative access,
	// or the system's last administrator. HTTP 403: the request is understood and the
	// caller is authorized, the target is simply not theirs to change.
	KindProtected Kind = "protected"
	KindInternal  Kind = "internal"
)

// Error is a typed admin-user service error.
type Error struct {
	Kind    Kind
	Code    int
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return "adminuser: <nil>"
	}
	if e.Err == nil {
		return fmt.Sprintf("adminuser: %s", e.Message)
	}
	return fmt.Sprintf("adminuser: %s: %v", e.Message, e.Err)
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
	ErrNotFound     = &Error{Kind: KindNotFound, Code: errcode.CodeUserNotFound}
	// ErrStudentIDOccupied and ErrEmailOccupied name the colliding column rather
	// than reporting a generic conflict: the administrator needs to know which field
	// to change, and both columns are unique so either can lose a race.
	ErrStudentIDOccupied = &Error{Kind: KindConflict, Code: errcode.CodeStudentIDOccupied}
	ErrEmailOccupied     = &Error{Kind: KindConflict, Code: errcode.CodeEmailAlreadyRegistered}
	ErrConflict          = &Error{Kind: KindConflict, Code: errcode.CodeConflict}
	ErrStateConflict     = &Error{Kind: KindStateConflict, Code: errcode.CodeValidationFailed}
	ErrProtected         = &Error{Kind: KindProtected, Code: errcode.CodeForbidden}
	ErrInternal          = &Error{Kind: KindInternal, Code: errcode.CodeInternal}
)

// newError builds a typed error carrying sentinel's Kind and Code. The message is a
// literal at the call site, never caller input; the cause travels in Err for the logs.
func newError(sentinel *Error, message string, cause error) error {
	return &Error{Kind: sentinel.Kind, Code: sentinel.Code, Message: message, Err: cause}
}

// internalError builds a KindInternal error and logs the cause, which would
// otherwise be discarded entirely: the client gets only a generic message.
func internalError(ctx context.Context, operation, message string, cause error) error {
	slog.ErrorContext(ctx, operation, "error", cause)
	return newError(ErrInternal, message, cause)
}
