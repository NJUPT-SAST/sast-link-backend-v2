package alumnirequest

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/turnstile"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/shared"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// Clock is the service's time source.
type Clock = auth.Clock

// auditTimeout bounds a detached audit write, matching adminuser.Service.audit so
// a review that already committed is still recorded when the caller disconnects.
const auditTimeout = 5 * time.Second

// Service implements the alumni account-request use cases.
type Service struct {
	Requests  Requests
	Users     Users
	Audit     AuditLogRepository
	Passwords PasswordHasher
	Captcha   CaptchaVerifier
	Limiter   EndpointLimiter
	Notifier  NotificationDispatcher
	Clock     Clock
	// SubmitRateLimit bounds submissions per IP and per student ID. Zero disables
	// the limiter call, which is only appropriate in tests.
	SubmitRateLimit int
	// ConsoleClientID is the built-in first-party client, recorded as the actor when
	// a review request carries no azp. Naming it explicitly keeps NULL in
	// actor_client_id meaning exactly one thing: no OAuth credential authorized the
	// action.
	ConsoleClientID string
}

func (s Service) now() time.Time {
	clock := s.Clock
	if clock == nil {
		clock = auth.SystemClock
	}
	return clock.Now().UTC()
}

// auditParams describes one audit row.
type auditParams struct {
	// UserID is the reviewer. Nil for a submission, which is unauthenticated and has
	// no subject to attribute it to.
	UserID        *int64
	ActorClientID string
	Action        string
	Resource      string
	ResourceID    string
	Success       bool
	ErrCode       int
	ClientIP      string
	UserAgent     string
	Detail        map[string]any
}

// audit records an action. Failures are logged, never returned: losing an audit
// row must not fail an otherwise valid change, but it must not pass silently.
func (s Service) audit(ctx context.Context, params auditParams) {
	if s.Audit == nil {
		return
	}
	success := params.Success
	entry := &model.AuditLog{
		UserID:    params.UserID,
		Action:    params.Action,
		Resource:  params.Resource,
		Success:   &success,
		ClientIP:  shared.NullableString(params.ClientIP),
		UserAgent: shared.NullableString(params.UserAgent),
		CreatedAt: s.now(),
	}
	if params.ResourceID != "" {
		resourceID := params.ResourceID
		entry.ResourceID = &resourceID
	}
	// A submission carries no OAuth credential, so actorClientID is not consulted
	// for it — attributing it to the console client would claim a credential
	// authorized something no credential touched.
	if params.UserID != nil {
		entry.ActorClientID = shared.NullableString(shared.ActorClientID(params.ActorClientID, s.ConsoleClientID))
	}
	if params.ErrCode != 0 {
		errCode := params.ErrCode
		entry.ErrCode = &errCode
	}
	if len(params.Detail) > 0 {
		encoded, err := json.Marshal(params.Detail)
		if err != nil {
			slog.ErrorContext(ctx, "marshal alumni request audit detail",
				"action", params.Action, "error", err)
			return
		}
		entry.Detail = model.JSONB(encoded)
	}
	// Detached so an action that already committed is still recorded when the caller
	// disconnects.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := s.Audit.Create(auditCtx, entry); err != nil {
		slog.ErrorContext(auditCtx, "record alumni request audit",
			"action", params.Action, "error", err)
	}
}

// mapCaptchaError translates a verifier error into this service's vocabulary.
// ErrUnavailable means the check could not be made (503, hide the entry point);
// anything else means the token was rejected (400, solve again). Collapsing them
// would report a challenge failure that never ran, or hide a missing secret.
func mapCaptchaError(err error) error {
	if errors.Is(err, turnstile.ErrUnavailable) {
		return newError(ErrUnavailable, "申请通道暂不可用，请稍后再试", err)
	}
	return newError(ErrCaptcha, "人机校验未通过，请重试", err)
}

// checkLimit applies one fixed-window bucket. Fail-open on a Redis error: losing
// the counter only widens the window, and the captcha is still in front.
func (s Service) checkLimit(ctx context.Context, subject string) error {
	if s.Limiter == nil || s.SubmitRateLimit <= 0 {
		return nil
	}
	result, err := s.Limiter.Allow(ctx, limitScope, subject)
	if err != nil {
		slog.WarnContext(ctx, "alumni request rate limit unavailable", "error", err)
		return nil
	}
	if !result.Allowed {
		return newError(ErrRateLimited, "提交过于频繁，请稍后再试", nil)
	}
	return nil
}

// requestView maps a stored ticket onto the console's read shape. ClientIP is not
// copied: see RequestView.
func requestView(request model.AlumniRequest) RequestView {
	return RequestView{
		ID:             request.ID,
		Name:           request.Name,
		StudentID:      request.StudentID,
		LoginEmail:     request.LoginEmail,
		PersonalEmail:  request.PersonalEmail,
		PhoneNumber:    request.PhoneNumber,
		QQNumber:       request.QQNumber,
		College:        string(request.College),
		Major:          request.Major,
		JoinYear:       request.JoinYear,
		DepartmentNote: request.DepartmentNote,
		Note:           request.Note,
		Status:         string(request.Status),
		RejectReason:   request.RejectReason,
		CreatedUserID:  request.CreatedUserID,
		ReviewedBy:     request.ReviewedBy,
		ReviewedAt:     request.ReviewedAt,
		NotifiedAt:     request.NotifiedAt,
		NotifyAttempts: request.NotifyAttempts,
		CreatedAt:      request.CreatedAt,
		UpdatedAt:      request.UpdatedAt,
	}
}

// resolvePaging clamps a page request to the documented bounds.
func resolvePaging(page, pageSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > validate.MaxPageSize {
		pageSize = validate.MaxPageSize
	}
	return page, pageSize
}

func formatID(id int64) string {
	return strconv.FormatInt(id, 10)
}
