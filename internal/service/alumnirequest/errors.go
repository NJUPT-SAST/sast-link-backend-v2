// Package alumnirequest implements the alumni account-request use cases without
// HTTP concerns.
//
// Kept separate from package adminuser: submission is this service's only
// unauthenticated write, so its error copy carries no console semantics and its
// inputs are stricter — major is mandatory here, since a blank one flags the
// approved account incomplete.
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
	// ErrEmailOccupied reuses the console's CodeEmailAlreadyRegistered rather than
	// taking a code of its own: the outcome a client must handle is identical, and
	// two codes for one observable outcome is drift waiting to happen.
	ErrEmailOccupied     = &Error{Kind: KindConflict, Code: errcode.CodeEmailAlreadyRegistered}
	ErrStudentIDOccupied = &Error{Kind: KindConflict, Code: errcode.CodeStudentIDOccupied}
	// ErrPending is the partial unique index on a pending student_id: one open
	// ticket per applicant. A rejected applicant may correct and resubmit, so this
	// says "your application is still open", not "you already applied".
	ErrPending = &Error{Kind: KindConflict, Code: errcode.CodeAlumniRequestPending}
	// ErrEmailPending is a pending ticket already carrying this address. Same
	// observable outcome as ErrPending (one open request per identity), so it
	// reuses CodeAlumniRequestPending with its own message.
	ErrEmailPending = &Error{Kind: KindConflict, Code: errcode.CodeAlumniRequestPending}
	// ErrRecoverNoTarget is a recovery submission whose student ID has no
	// account: the applicant needs the provision flow, not recovery. 400 so a
	// client can offer the switch instead of leaving them on a form that cannot
	// succeed.
	ErrRecoverNoTarget = &Error{Kind: KindInvalidInput, Code: errcode.CodeBadRequest}
	// ErrLoginEmailMismatch is a recovery submission whose login_email does not
	// name the account its student ID points at. The school address is guessable,
	// so this is data integrity rather than authentication — but it must match
	// for approval to touch the right account.
	ErrLoginEmailMismatch = &Error{Kind: KindInvalidInput, Code: errcode.CodeBadRequest}
	// ErrStaleRecoverTicket is the same disagreement surfaced from inside the
	// approval transaction (the row could have drifted after the pre-check, or
	// the pre-check was skipped). A 422 telling the reviewer to reject and ask
	// for a fresh submission.
	ErrStaleRecoverTicket = &Error{Kind: KindStateConflict, Code: errcode.CodeValidationFailed}
	// ErrAccountClosedForRecover is an approval whose target account is
	// soft-deleted: no access can be restored on a closed account.
	ErrAccountClosedForRecover = &Error{Kind: KindStateConflict, Code: errcode.CodeValidationFailed}
	// ErrIdentityLimitReached names the per-account cap on additional email binds
	// a recovery approval would exceed. Same observable outcome as the
	// self-service bind cap and the admin rescue bind, so it reuses
	// CodeIdentityLimitReached.
	ErrIdentityLimitReached = &Error{Kind: KindConflict, Code: errcode.CodeIdentityLimitReached}
	// ErrTargetVanished is a recovery approval whose student ID stopped resolving
	// to an account between submission and approval: a concurrent removal or
	// import drift. A plain conflict — the reviewer re-checks the queue rather
	// than retrying blind.
	ErrTargetVanished = &Error{Kind: KindConflict, Code: errcode.CodeConflict}
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

// newError builds a typed error carrying sentinel's Kind and Code. The message is a
// literal at the call site, never caller input — an anonymous submit path must not
// reflect submissions back.
func newError(sentinel *Error, message string, cause error) error {
	return &Error{Kind: sentinel.Kind, Code: sentinel.Code, Message: message, Err: cause}
}

// internalError builds a KindInternal error and logs the cause, which would
// otherwise be discarded entirely: the client gets only a generic message.
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
