// Package alumnirequest implements the alumni account-request use cases without
// HTTP concerns.
//
// Kept separate from package adminuser even though approval provisions an
// account through the same repository call: the surfaces have opposite trust
// properties. Submission is the service's only unauthenticated write, so its
// error copy must not carry console semantics and its inputs are stricter than
// the console's — major is mandatory here because a blank one is what V010's
// generated column flags as an incomplete profile, which would send every
// approved alumnus straight to a completion page on first login.
package alumnirequest

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
	// KindStateConflict is a review action on a ticket that already carries a
	// verdict, or a notification resend for one that has none yet. HTTP 422: the
	// request is well formed and the ticket exists, the transition is what is
	// refused.
	KindStateConflict Kind = "state_conflict"
	// KindCaptchaFailed is a rejected human-verification token. HTTP 400: the
	// submitter can solve the challenge again and retry.
	KindCaptchaFailed Kind = "captcha_failed"
	// KindUnavailable is an inability to verify rather than a failed verification.
	// HTTP 503: nothing the submitter does will help, so the client should hide the
	// entry point instead of offering a form that cannot succeed.
	KindUnavailable Kind = "unavailable"
	KindRateLimited Kind = "rate_limited"
	KindInternal    Kind = "internal"
)

// Error is a typed alumni-request service error.
type Error struct {
	Kind    Kind
	Code    int
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return "alumnirequest: <nil>"
	}
	if e.Err == nil {
		return fmt.Sprintf("alumnirequest: %s", e.Message)
	}
	return fmt.Sprintf("alumnirequest: %s: %v", e.Message, e.Err)
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
	ErrEmailDomain  = &Error{Kind: KindInvalidInput, Code: errcode.CodeEmailDomainNotAllowed}
	ErrNotFound     = &Error{Kind: KindNotFound, Code: errcode.CodeAlumniRequestNotFound}
	// ErrEmailOccupied deliberately reuses CodeEmailAlreadyRegistered rather than
	// taking a code of its own. The outcome a client must handle is identical to the
	// console's, and errcode's rule is that the constant set is exactly what clients
	// can observe: two codes for one observable outcome is drift waiting to happen.
	ErrEmailOccupied     = &Error{Kind: KindConflict, Code: errcode.CodeEmailAlreadyRegistered}
	ErrStudentIDOccupied = &Error{Kind: KindConflict, Code: errcode.CodeStudentIDOccupied}
	// ErrPending is the partial unique index on a pending student_id: one open
	// ticket per applicant. A rejected applicant may correct and resubmit, so this
	// says "your application is still open", not "you already applied".
	ErrPending = &Error{Kind: KindConflict, Code: errcode.CodeAlumniRequestPending}
	// ErrAlreadyReviewed is a second verdict on a ticket that has one. What a
	// double-clicked approve button sees.
	ErrAlreadyReviewed = &Error{Kind: KindStateConflict, Code: errcode.CodeAlumniRequestReviewed}
	// ErrNotReviewed is a notification resend for a ticket with no verdict: there is
	// no result to notify anyone about.
	ErrNotReviewed = &Error{Kind: KindStateConflict, Code: errcode.CodeValidationFailed}
	ErrCaptcha     = &Error{Kind: KindCaptchaFailed, Code: errcode.CodeCaptchaFailed}
	ErrUnavailable = &Error{Kind: KindUnavailable, Code: errcode.CodeAlumniRequestUnavailable}
	ErrRateLimited = &Error{Kind: KindRateLimited, Code: errcode.CodeRateLimited}
	ErrInternal    = &Error{Kind: KindInternal, Code: errcode.CodeInternal}
)

// newError builds a typed error carrying sentinel's Kind and Code.
//
// The message is always a literal at the call site and never interpolates caller
// input: descriptions reach the client verbatim, and this service's submit path
// is unauthenticated, so echoing a submitted value back would make an anonymous
// endpoint a reflection point.
func newError(sentinel *Error, message string, cause error) error {
	return &Error{Kind: sentinel.Kind, Code: sentinel.Code, Message: message, Err: cause}
}

// internalError builds a KindInternal error and logs the cause.
//
// The client is told nothing beyond a generic message, so unless the cause is
// logged here it is discarded entirely: the HTTP layer replaces it and the
// request logger records only the status.
func internalError(ctx context.Context, operation, message string, cause error) error {
	slog.ErrorContext(ctx, operation, "error", cause)
	return newError(ErrInternal, message, cause)
}

// errorCode returns the business code carried by err, or 0.
func errorCode(err error) int {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return 0
}
