package adminclient

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
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

// checkProtected refuses an update that would break the built-in client or weaken a
// client that currently holds a capability scope.
//
// It keys on the stored row, never on the submitted fields, which is what makes it
// unbypassable by splitting a change across two requests.
func (s Service) checkProtected(current *model.OAuthClient, input UpdateClientInput) error {
	if current == nil {
		return nil
	}
	if protected := strings.TrimSpace(s.ProtectedClientID); protected != "" && current.ClientID == protected {
		// Renaming is allowed: client_name is cosmetic and appears only on the consent
		// page. The rest are not.
		if input.IsActive != nil && !*input.IsActive {
			return newError(ErrProtectedClient, "内置客户端不可停用", nil)
		}
		if input.RedirectURIs != nil {
			// Would let an administrator redirect first-party authorization codes to a host
			// of their choosing — the one registration this service cannot afford to have
			// pointed elsewhere.
			return newError(ErrProtectedClient, "内置客户端的 redirect_uris 不可通过本接口修改", nil)
		}
		if input.Scope != nil {
			// cmd/api asserts this client's scopes against scope.InternalSessionScopes at
			// startup, so editing them here is a delayed self-destruct: the running process
			// keeps working, and the next restart refuses to boot with no way back except
			// direct database access. Narrowing them would additionally trip the
			// scope-removal revocation below and cut every user's internal session at once.
			return newError(ErrProtectedClient, "内置客户端的 scopes 不可通过本接口修改", nil)
		}
		if input.GrantTypes != nil {
			// Frozen like scopes. V003 seeds the canonical authorization_code +
			// refresh_token pair, the console's own OAuth session renews through the
			// refresh grant (the token endpoint live-checks grant_types, so narrowing it
			// cuts renewal immediately), and V003's drift detection holds the row to the
			// seeded value — editing it either breaks the console's token renewal or
			// aborts the next migrate up. There is no legitimate value other than the
			// seeded one, so the console is frozen alongside a delegate rather than
			// privileged to shoot itself.
			return newError(ErrProtectedClient, "内置客户端的 grant_types 不可通过本接口修改", nil)
		}
		return nil
	}
	// A capability client is whichever registration carries an admin or user scope,
	// so the guard is a predicate over the stored scopes rather than a match against
	// a known client_id.
	if !scope.ContainsAdmin([]string(current.Scopes)) && !scope.ContainsUser([]string(current.Scopes)) {
		return nil
	}
	if input.RedirectURIs != nil {
		// This client's authorization codes carry capability scopes, so its
		// redirect_uris are as sensitive as the built-in client's: rewriting them
		// points an authorization code at a host of the operator's choosing.
		return newError(ErrProtectedClient, "持有能力 scope 的客户端 redirect_uris 不可通过本接口修改", nil)
	}
	// Only the console may administer a client that holds a capability scope.
	// Without this, one scoped client could re-enable another that an operator
	// disabled — the documented kill switch — or edit it back into usefulness,
	// making the set of capability clients self-sustaining rather than
	// console-controlled.
	//
	// Disabling such a client from the console remains permitted: is_active=false
	// already revokes its live tokens, and unlike the console there is no lockout
	// risk, because nothing about administering this service depends on that client.
	if !s.actorIsConsole(input.ActorClientID) {
		return newError(ErrProtectedClient, "持有能力 scope 的客户端只能由控制台维护", nil)
	}
	return nil
}

// actorIsConsole reports whether this call was authorized by the built-in console
// client rather than by an admin-scoped token.
//
// An empty azp counts as the console: nothing can mint an azp-less token today, so
// the only tokens without one are built-in sessions predating the claim — the same
// reading middleware.AuthenticateAdminDelegated applies. Fails closed when
// ProtectedClientID is unset: an unknown console identity cannot be matched, so no
// third-party actor is treated as one.
func (s Service) actorIsConsole(actorClientID string) bool {
	actor := strings.TrimSpace(actorClientID)
	return actor == "" || actor == strings.TrimSpace(s.ProtectedClientID)
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
