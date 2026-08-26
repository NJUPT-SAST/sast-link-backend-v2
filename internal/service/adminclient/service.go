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
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/shared"
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
	// ProtectedClientID is the built-in first-party client_id the internal session
	// flow depends on. Disabling or reconfiguring it is an unrecoverable lockout —
	// login, refresh and registration stop for everyone, including the administrator —
	// so this service refuses such edits. Empty disables the guard; cmd/api always
	// sets it from INTERNAL_OAUTH_CLIENT_ID.
	ProtectedClientID string
}

func (s Service) now() time.Time {
	clock := s.Clock
	if clock == nil {
		clock = auth.SystemClock
	}
	// UTC, so audit timestamps stay uniform with every other row's Z suffix.
	return clock.Now().UTC()
}

func (s Service) newClientID() (string, error) {
	if s.NewClientID != nil {
		return s.NewClientID()
	}
	return newClientID()
}

// checkProtected refuses an update that would break the built-in client or weaken a
// client holding a capability scope. It keys on the stored row, never the submitted
// fields, so a change cannot be split across two requests to bypass it.
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
			// Redirecting first-party authorization codes to an arbitrary host is a
			// takeover this service cannot afford.
			return newError(ErrProtectedClient, "内置客户端的 redirect_uris 不可通过本接口修改", nil)
		}
		if input.Scope != nil {
			// Editing the scopes is a delayed self-destruct — the next restart refuses
			// to boot — and narrowing them would cut every user's internal session.
			return newError(ErrProtectedClient, "内置客户端的 scopes 不可通过本接口修改", nil)
		}
		if input.GrantTypes != nil {
			// Editing the grants would break the console's token renewal or abort the
			// next migrate up; no other value is legitimate.
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
		// Its authorization codes carry capability scopes, so rewriting the callbacks
		// points an authorization code at a host of the operator's choosing.
		return newError(ErrProtectedClient, "持有能力 scope 的客户端 redirect_uris 不可通过本接口修改", nil)
	}
	// Only the console may administer a capability client, or one scoped client could
	// re-enable another an operator disabled. Disabling one remains console-permitted:
	// there is no lockout risk.
	if !s.actorIsConsole(input.ActorClientID) {
		return newError(ErrProtectedClient, "持有能力 scope 的客户端只能由控制台维护", nil)
	}
	return nil
}

// actorIsConsole reports whether this call was authorized by the built-in console
// client rather than by an admin-scoped token. An empty azp counts as the console;
// fails closed when ProtectedClientID is unset.
func (s Service) actorIsConsole(actorClientID string) bool {
	actor := strings.TrimSpace(actorClientID)
	return actor == "" || actor == strings.TrimSpace(s.ProtectedClientID)
}

// auditParams describes one admin audit row. A struct rather than positional
// parameters, which would invite a transposition.
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
		ClientIP:      shared.NullableString(params.ClientIP),
		UserAgent:     shared.NullableString(params.UserAgent),
		ActorClientID: shared.NullableString(shared.ActorClientID(params.ActorClientID, s.ProtectedClientID)),
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
	// Detached so an action that already committed (disabling a client and revoking
	// its tokens) is still recorded when the caller disconnects.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := s.Audit.Create(auditCtx, entry); err != nil {
		slog.ErrorContext(auditCtx, "record admin oauth client audit",
			"action", action, "error", err)
	}
}
