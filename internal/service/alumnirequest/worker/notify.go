// Package alumnirequestworker delivers account-request result emails outside the
// review request path.
package alumnirequestworker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/mailer"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/alumnirequest"
)

// defaultQueueSize bounds the pending notifications; a bounded queue is what makes
// Enqueue non-blocking.
const defaultQueueSize = 64

// writeTimeout bounds the delivery-state writes, detached from the caller's context
// so a delivered email is not left looking undelivered.
const writeTimeout = 5 * time.Second

// Requests records delivery state.
type Requests interface {
	// MarkNotifyAttempt increments the counter before a send is attempted.
	MarkNotifyAttempt(ctx context.Context, requestID int64) error
	// MarkNotified records a confirmed delivery.
	MarkNotified(ctx context.Context, requestID int64, now time.Time) error
}

// Mailer delivers the result email.
type Mailer interface {
	SendAlumniRequestResult(ctx context.Context, to string, result mailer.AlumniResult) error
}

// Notifier consumes queued account-request notifications.
type Notifier struct {
	jobs     chan alumnirequest.NotificationJob
	Requests Requests
	Mailer   Mailer
	// ResetURL is the password-reset page an approved applicant is sent to.
	ResetURL string
	// SupportEmail is the appeal channel quoted in a rejection.
	SupportEmail string
	Clock        func() time.Time
}

// New builds a notifier with a bounded queue.
func New(requests Requests, emailer Mailer, resetURL, supportEmail string) *Notifier {
	return &Notifier{
		jobs:         make(chan alumnirequest.NotificationJob, defaultQueueSize),
		Requests:     requests,
		Mailer:       emailer,
		ResetURL:     resetURL,
		SupportEmail: supportEmail,
	}
}

// EnqueueAlumniNotification queues one notification, reporting whether it fit.
//
// Non-blocking: the review has already committed, so the response must not wait
// on an email, and a full queue must not turn a successful approval into a failed
// request. A false answer is surfaced to the reviewer as notify_enqueued.
func (w *Notifier) EnqueueAlumniNotification(job alumnirequest.NotificationJob) bool {
	if w == nil || w.jobs == nil {
		return false
	}
	select {
	case w.jobs <- job:
		return true
	default:
		return false
	}
}

// Run consumes the queue until ctx is cancelled.
func (w *Notifier) Run(ctx context.Context) error {
	if w == nil || w.jobs == nil || w.Requests == nil || w.Mailer == nil {
		return fmt.Errorf("alumni notification worker requires queue, requests and mailer")
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case job := <-w.jobs:
			w.process(ctx, job)
		}
	}
}

func (w *Notifier) now() time.Time {
	if w.Clock != nil {
		return w.Clock().UTC()
	}
	return time.Now().UTC()
}

// process delivers one notification and records the outcome. The attempt is
// counted before the send, so a process killed mid-send leaves "tried, not
// confirmed delivered" — the truth — instead of an untouched ticket.
func (w *Notifier) process(ctx context.Context, job alumnirequest.NotificationJob) {
	if err := w.markAttempt(ctx, job.RequestID); err != nil {
		// Logged, not fatal: failing to count the attempt must not stop the email the
		// applicant is waiting for.
		logFailure(ctx, job, "mark_attempt", err)
	}

	err := w.Mailer.SendAlumniRequestResult(ctx, job.Recipient, mailer.AlumniResult{
		Name:         job.Name,
		Approved:     job.Approved,
		RejectReason: job.RejectReason,
		ResetURL:     w.ResetURL,
		SupportEmail: w.SupportEmail,
	})
	if err != nil {
		// On an approval a lost email means the applicant does not know their account
		// exists, so the log names the ticket for a manual resend.
		logFailure(ctx, job, "smtp", err)
		return
	}

	if err := w.markNotified(ctx, job.RequestID); err != nil {
		// The email did go out. A failed write here only means the console will show
		// the ticket as un-notified, which is a resend the applicant can absorb -
		// unlike a missing email.
		logFailure(ctx, job, "mark_notified", err)
	}
}

func (w *Notifier) markAttempt(ctx context.Context, requestID int64) error {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	return w.Requests.MarkNotifyAttempt(writeCtx, requestID)
}

func (w *Notifier) markNotified(ctx context.Context, requestID int64) error {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	return w.Requests.MarkNotified(writeCtx, requestID, w.now())
}

// logFailure records a delivery problem with the ticket id, which is what an
// administrator needs to drive the resend endpoint.
func logFailure(ctx context.Context, job alumnirequest.NotificationJob, stage string, err error) {
	if ctx.Err() != nil {
		return
	}
	slog.ErrorContext(ctx, "alumni request notification failed",
		"operation", "alumni_request_notify",
		"stage", stage,
		"request_id", job.RequestID,
		"approved", job.Approved,
		"error", err)
}
