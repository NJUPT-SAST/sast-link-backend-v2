package adminuser

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// Clock is the service's time source.
type Clock = auth.Clock

// auditTimeout bounds a detached audit write, matching adminclient.Service.audit
// so an admin action that already committed is still recorded when the caller
// disconnects.
const auditTimeout = 5 * time.Second

// Service implements the administrative user-management use cases.
type Service struct {
	Users     UserRepository
	Audit     AuditLogRepository
	Blacklist TokenBlacklist
	Devices   DeviceStore
	Clock     Clock
	// Passwords hashes the initial password for provisioned accounts.
	Passwords auth.PasswordHasher
	// ConsoleClientID is the built-in first-party client, recorded as the actor when
	// a request carries no azp (first-party sessions predate the claim). Naming it
	// explicitly keeps NULL in actor_client_id meaning exactly one thing: no OAuth
	// credential authorized the action.
	ConsoleClientID string
}

// actorClientID resolves what to record as the acting client: the token's azp when
// present, otherwise the console. Returns empty when neither is known, which the
// caller stores as NULL.
func (s Service) actorClientID(tokenClientID string) string {
	if tokenClientID != "" {
		return tokenClientID
	}
	return s.ConsoleClientID
}

func (s Service) now() time.Time {
	clock := s.Clock
	if clock == nil {
		clock = auth.SystemClock
	}
	return clock.Now().UTC()
}

// auditParams describes one admin audit row. A struct rather than positional
// parameters, which would invite a transposition.
type auditParams struct {
	AdminUserID int64
	// ActorClientID is the azp of the token that authorized this action. Empty means
	// the request came from the console, which the audit records explicitly rather
	// than as NULL — see Service.ConsoleClientID.
	ActorClientID string
	Action        string
	TargetUserID  int64
	Success       bool
	ErrCode       int
	ClientIP      string
	UserAgent     string
	Detail        map[string]any
}

// audit records an admin action. Failures are logged, never returned: losing an
// audit row must not fail an otherwise valid change, but it must not pass
// silently either.
func (s Service) audit(ctx context.Context, params auditParams) {
	if s.Audit == nil {
		return
	}
	resourceID := strconv.FormatInt(params.TargetUserID, 10)
	action := params.Action
	success := params.Success
	entry := &model.AuditLog{
		UserID:        &params.AdminUserID,
		Action:        action,
		Resource:      auditResourceUser,
		ResourceID:    &resourceID,
		Success:       &success,
		ClientIP:      nullableString(params.ClientIP),
		UserAgent:     nullableString(params.UserAgent),
		ActorClientID: nullableString(s.actorClientID(params.ActorClientID)),
		CreatedAt:     s.now(),
	}
	if params.ErrCode != 0 {
		errCode := params.ErrCode
		entry.ErrCode = &errCode
	}
	detail := params.Detail
	if len(detail) > 0 {
		encoded, err := json.Marshal(detail)
		if err != nil {
			slog.ErrorContext(ctx, "marshal admin user audit detail", "action", action, "error", err)
			return
		}
		entry.Detail = model.JSONB(encoded)
	}
	// Detached so an action that already committed (closing an account and revoking
	// its tokens) is still recorded when the caller disconnects.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := s.Audit.Create(auditCtx, entry); err != nil {
		slog.ErrorContext(auditCtx, "record admin user audit", "action", action, "error", err)
	}
}

// deliverBlacklist clears the auth-state cache entries for the revoked access
// tokens. The durable delivery is the outbox row written in the revoking
// transaction (the worker retries until it lands); this synchronous call closes
// the stale window immediately so a just-revoked token is rejected on the next
// request rather than riding out the cache TTL.
func (s Service) deliverBlacklist(ctx context.Context, entries []model.BlacklistEntry, now time.Time) {
	if s.Blacklist == nil || len(entries) == 0 {
		return
	}
	jtis := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.ExpiresAt.Sub(now) <= 0 {
			continue
		}
		jtis = append(jtis, entry.TokenID)
	}
	if len(jtis) == 0 {
		return
	}
	if err := s.Blacklist.DeleteAuthStates(ctx, jtis); err != nil {
		slog.WarnContext(ctx, "invalidate admin user revocation auth-state cache", "count", len(jtis), "error", err)
	}
}

func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
