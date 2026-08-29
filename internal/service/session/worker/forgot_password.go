package sessionworker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/mailer"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
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
		return
	}
	if err != nil {
		logForgotPasswordFailure(ctx, "lookup", err)
		return
	}
	code, err := session.GenerateVerificationCode()
	if err != nil {
		logForgotPasswordFailure(ctx, "generate_code", err)
		return
	}
	purpose := string(mailer.VerificationPurposeResetPassword)
	if err := w.Codes.SaveVerificationCode(ctx, purpose, validate.StripSubaddress(job.Email), code, forgotPasswordCodeTTL); err != nil {
		logForgotPasswordFailure(ctx, "save_code", err)
		return
	}
	if err := w.Mailer.SendVerificationCode(ctx, job.Email, code, mailer.VerificationPurposeResetPassword); err != nil {
		logForgotPasswordFailure(ctx, "smtp", err)
		return
	}
	if w.Audit != nil {
		success := true
		clientIP := job.ClientIP
		userAgent := job.UserAgent
		entry := &model.AuditLog{
			UserID: &user.ID, Action: "forgot_password_send_code", Resource: "verification_code",
			Success: &success, ClientIP: &clientIP, UserAgent: &userAgent,
		}
		if err := w.Audit.Create(ctx, entry); err != nil && ctx.Err() == nil {
			logForgotPasswordFailure(ctx, "audit", err)
		}
	}
}

func logForgotPasswordFailure(ctx context.Context, stage string, err error) {
	if ctx.Err() == nil {
		slog.ErrorContext(ctx, "forgot password delivery failed", "operation", "forgot_password_send_code", "stage", stage, "error", err)
	}
}
