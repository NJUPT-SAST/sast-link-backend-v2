package adminclient

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// Clock is the service's time source.
type Clock = auth.Clock

// auditTimeout bounds a detached audit write, matching oauth.Service.audit so an
// admin action that already committed is still recorded when the caller disconnects.
const auditTimeout = 5 * time.Second

// Service implements the administrative OAuth client registry.
type Service struct {
	Clients   ClientRepository
	Blacklist TokenBlacklist
	Audit     AuditRepository
	Secrets   auth.ClientSecretHasher
	// NewClientID generates the public client identifier. Overridable for tests that
	// need a deterministic value.
	NewClientID func() (string, error)
	Clock       Clock
	// ProtectedClientID is the built-in first-party client_id that the internal
	// session flow depends on. It cannot be disabled or have its redirect_uris
	// rewritten through this service.
	//
	// Required in production. Disabling that client is an unrecoverable lockout:
	// session.findInternalClient resolves it through an is_active filter, so the flag
	// flip breaks login, refresh and registration for everyone — including the
	// administrator who would flip it back — and the same call revokes every internal
	// session token, since they all belong to that client. Recovery would need direct
	// database access.
	//
	// Empty disables the guard, which is why cmd/api always sets it from
	// INTERNAL_OAUTH_CLIENT_ID rather than relying on a default here.
	ProtectedClientID string
}

func (s Service) now() time.Time {
	clock := s.Clock
	if clock == nil {
		clock = auth.SystemClock
	}
	// UTC like the oauth and adminuser services: audit timestamps must not mix
	// local offsets with the Z every other row carries.
	return clock.Now().UTC()
}

// actorClientID resolves what to record as the acting client: the token's azp when
// present, otherwise the console.
//
// ProtectedClientID doubles as the console's identity here rather than a second
// field holding the same value. Both come from INTERNAL_OAUTH_CLIENT_ID, and one
// field cannot drift from itself — a separate ConsoleClientID could be wired to a
// different value, and the audit trail would then name a client that never acted.
func (s Service) actorClientID(tokenClientID string) string {
	if tokenClientID != "" {
		return tokenClientID
	}
	return strings.TrimSpace(s.ProtectedClientID)
}

func (s Service) newClientID() (string, error) {
	if s.NewClientID != nil {
		return s.NewClientID()
	}
	return newClientID()
}

// checkProtected refuses an update that would break the built-in client.
//
// Renaming it is allowed: client_name is cosmetic and appears only on the consent
// page. Disabling it and rewriting its redirect_uris are not — the first is the
// lockout described on ProtectedClientID, and the second would let an
// administrator redirect first-party authorization codes to a host of their
// choosing, which is the one registration this service cannot afford to have
// pointed elsewhere.
func (s Service) checkProtected(current *model.OAuthClient, input UpdateClientInput) error {
	if current == nil {
		return nil
	}
	if protected := strings.TrimSpace(s.ProtectedClientID); protected != "" && current.ClientID == protected {
		if input.IsActive != nil && !*input.IsActive {
			return newError(ErrProtectedClient, "内置客户端不可停用", nil)
		}
		if input.RedirectURIs != nil {
			return newError(ErrProtectedClient, "内置客户端的 redirect_uris 不可通过本接口修改", nil)
		}
		return nil
	}
	// The delegated-administration client's authorization codes carry admin scopes, so
	// its redirect_uris are as sensitive as the built-in client's: rewriting them
	// points an administrative code at a host of the operator's choosing.
	//
	// Disabling it, unlike the built-in client, is deliberately permitted. It is the
	// kill switch for delegated administration — is_active=false already revokes the
	// client's live tokens — and unlike the console there is no lockout risk, because
	// nothing about administering this service depends on the ops tool working.
	if current.ClientID == model.AdminDelegatedClientID && input.RedirectURIs != nil {
		return newError(ErrProtectedClient, "委派管理客户端的 redirect_uris 不可通过本接口修改", nil)
	}
	return nil
}

// auditParams describes one admin audit row. A struct rather than positional
// parameters, for the same reason as adminuser.auditParams: too many adjacent
// strings for a transposition to be caught by the compiler.
type auditParams struct {
	AdminUserID int64
	// ActorClientID is the azp of the token that authorized this action. Empty means
	// the console, recorded as ConsoleClientID.
	ActorClientID string
	Action        string
	ResourceID    *string
	Success       bool
	ErrCode       int
	ClientIP      string
	UserAgent     string
	Detail        map[string]any
}

// audit records an admin action. Failures are logged, never returned: losing an
// audit row must not fail an otherwise valid registration change, but it must not
// pass silently either.
func (s Service) audit(ctx context.Context, params auditParams) {
	if s.Audit == nil {
		return
	}
	action := params.Action
	success := params.Success
	entry := &model.AuditLog{
		UserID:        &params.AdminUserID,
		Action:        action,
		Resource:      auditResource,
		ResourceID:    params.ResourceID,
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
			slog.ErrorContext(ctx, "marshal admin oauth client audit detail",
				"action", action, "error", err)
			return
		}
		entry.Detail = model.JSONB(encoded)
	}
	// Detached like oauth.Service.audit: an admin action that already committed
	// (e.g. disabling a client and revoking its tokens) must still be recorded when
	// the caller goes away, or the audit log loses exactly the events an aborted
	// request produced.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := s.Audit.Create(auditCtx, entry); err != nil {
		slog.ErrorContext(auditCtx, "record admin oauth client audit",
			"action", action, "error", err)
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
		slog.WarnContext(ctx, "invalidate client revocation auth-state cache", "count", len(jtis), "error", err)
	}
}

func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
