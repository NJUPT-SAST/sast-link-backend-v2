package sessionworker

import (
	"encoding/json"

	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/mailer"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/shared"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

const (
	defaultForgotPasswordQueueSize = 64
	forgotPasswordCodeTTL          = 5 * time.Minute
)

type ForgotPasswordUsers interface {
	// FindAuthUserByLoginIdentifier returns the scalar columns without preloads;
	// it accepts a login email or an other_mail identity.
	FindAuthUserByLoginIdentifier(ctx context.Context, identifier string) (*model.User, error)
}

type ForgotPasswordCodes interface {
	SaveVerificationCode(ctx context.Context, purpose, email, code string, ttl time.Duration) error
}

type ForgotPasswordAudit interface {
	Create(ctx context.Context, entry *model.AuditLog) error
}

// ForgotPassword dispatches account-sensitive reset email work outside the
// anonymous request path; enqueue is non-blocking and bounded.
type ForgotPassword struct {
	jobs   chan session.ForgotPasswordJob
	Users  ForgotPasswordUsers
	Codes  ForgotPasswordCodes
	Mailer session.Mailer
	Audit  ForgotPasswordAudit
}

func NewForgotPassword(users ForgotPasswordUsers, codes ForgotPasswordCodes, emailer session.Mailer, audit ForgotPasswordAudit) *ForgotPassword {
	return &ForgotPassword{
		jobs:  make(chan session.ForgotPasswordJob, defaultForgotPasswordQueueSize),
		Users: users, Codes: codes, Mailer: emailer, Audit: audit,
	}
}

func (w *ForgotPassword) EnqueueForgotPassword(job session.ForgotPasswordJob) bool {
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

func (w *ForgotPassword) Run(ctx context.Context) error {
	if w == nil || w.jobs == nil || w.Users == nil || w.Codes == nil || w.Mailer == nil {
		return fmt.Errorf("forgot password worker requires queue, users, codes and mailer")
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

func (w *ForgotPassword) process(ctx context.Context, job session.ForgotPasswordJob) {
	user, err := w.Users.FindAuthUserByLoginIdentifier(ctx, job.Email)
	if errors.Is(err, repository.ErrNotFound) {
		// The request-time existence check and this lookup race an account
		// closing in between: there is no one left to deliver to and nothing
		// wrong with the machinery, so no row.
		return
	}
	if err != nil {
		logForgotPasswordFailure(ctx, "lookup", err)
		w.auditDeliveryFailure(ctx, job, nil, "lookup", errcode.CodeInternal)
		return
	}
	code, err := session.GenerateVerificationCode()
	if err != nil {
		logForgotPasswordFailure(ctx, "generate_code", err)
		w.auditDeliveryFailure(ctx, job, &user.ID, "generate_code", errcode.CodeInternal)
		return
	}
	purpose := string(mailer.VerificationPurposeResetPassword)
	if err := w.Codes.SaveVerificationCode(ctx, purpose, validate.StripSubaddress(job.Email), code, forgotPasswordCodeTTL); err != nil {
		logForgotPasswordFailure(ctx, "save_code", err)
		w.auditDeliveryFailure(ctx, job, &user.ID, "save_code", errcode.CodeDependencyUnavailable)
		return
	}
	if err := w.Mailer.SendVerificationCode(ctx, job.Email, code, mailer.VerificationPurposeResetPassword); err != nil {
		logForgotPasswordFailure(ctx, "smtp", err)
		w.auditDeliveryFailure(ctx, job, &user.ID, "smtp", errcode.CodeEmailDeliveryFailed)
		return
	}
	if w.Audit != nil {
		success := true
		// NullableString keeps the V007 contract: a missing IP/UA is NULL, not
		// the empty string, so NULL stays unambiguous as "no value recorded"
		// across every audit writer in the service.
		entry := &model.AuditLog{
			UserID: &user.ID, Action: "forgot_password_send_code", Resource: "verification_code",
			Success: &success, ClientIP: shared.NullableString(job.ClientIP), UserAgent: shared.NullableString(job.UserAgent),
		}
		if err := w.Audit.Create(ctx, entry); err != nil && ctx.Err() == nil {
			logForgotPasswordFailure(ctx, "audit", err)
		}
	}
}

// auditDeliveryFailure records the silent leg of this async flow: the request
// already answered 200, so a job that dies in process() leaves the user
// waiting for an email that cannot arrive. The queue-full refusal answers
// 50300 and is visible, but a fast-failing relay empties the queue without
// ever tripping it — a failed row per dropped delivery is what makes both
// shapes queryable in the 90-day trail. The row carries the stage and the
// business code, never the raw error text: the text lives in the log line, and
// the audit surface keeps its fixed vocabulary.
func (w *ForgotPassword) auditDeliveryFailure(ctx context.Context, job session.ForgotPasswordJob, userID *int64, stage string, code int) {
	if w.Audit == nil {
		return
	}
	success := false
	encoded, err := json.Marshal(map[string]any{"stage": stage, "email": job.Email})
	if err != nil {
		slog.ErrorContext(ctx, "marshal forgot-password audit detail", "stage", stage, "error", err)
		return
	}
	entry := &model.AuditLog{
		UserID: userID, Action: "forgot_password_send_code", Resource: "verification_code",
		Success: &success, ErrCode: &code,
		// NullableString keeps the V007 contract: a missing IP/UA is NULL, not
		// the empty string, so NULL stays unambiguous as "no value recorded"
		// across every audit writer in the service.
		ClientIP: shared.NullableString(job.ClientIP), UserAgent: shared.NullableString(job.UserAgent),
		Detail: model.JSONB(encoded),
	}
	if err := w.Audit.Create(ctx, entry); err != nil && ctx.Err() == nil {
		logForgotPasswordFailure(ctx, "audit", err)
	}
}

func logForgotPasswordFailure(ctx context.Context, stage string, err error) {
	if ctx.Err() == nil {
		slog.ErrorContext(ctx, "forgot password delivery failed", "operation", "forgot_password_send_code", "stage", stage, "error", err)
	}
}
