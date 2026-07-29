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
	return clock.Now()
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
	protected := strings.TrimSpace(s.ProtectedClientID)
	if protected == "" || current == nil || current.ClientID != protected {
		return nil
	}
	if input.IsActive != nil && !*input.IsActive {
		return newError(ErrProtectedClient, "内置客户端不可停用", nil)
	}
	if input.RedirectURIs != nil {
		return newError(ErrProtectedClient, "内置客户端的 redirect_uris 不可通过本接口修改", nil)
	}
	return nil
}

// audit records an admin action. Failures are logged, never returned: losing an
// audit row must not fail an otherwise valid registration change, but it must not
// pass silently either.
func (s Service) audit(
	ctx context.Context,
	adminUserID int64,
	action string,
	resourceID *string,
	success bool,
	errCode int,
	clientIP, userAgent string,
	detail map[string]any,
) {
	if s.Audit == nil {
		return
	}
	entry := &model.AuditLog{
		UserID:     &adminUserID,
		Action:     action,
		Resource:   auditResource,
		ResourceID: resourceID,
		Success:    &success,
		ClientIP:   nullableString(clientIP),
		UserAgent:  nullableString(userAgent),
		CreatedAt:  s.now(),
	}
	if errCode != 0 {
		entry.ErrCode = &errCode
	}
	if len(detail) > 0 {
		encoded, err := json.Marshal(detail)
		if err != nil {
			slog.ErrorContext(ctx, "marshal admin oauth client audit detail",
				"action", action, "error", err)
			return
		}
		entry.Detail = model.JSONB(encoded)
	}
	if err := s.Audit.Create(ctx, entry); err != nil {
		slog.ErrorContext(ctx, "record admin oauth client audit",
			"action", action, "error", err)
	}
}

// deliverBlacklist pushes revoked JTIs to the fast-reject cache. The durable outbox
// rows were written in the revoking transaction, so a failure here only delays that
// path; the middleware's DB check rejects these tokens either way.
func (s Service) deliverBlacklist(ctx context.Context, entries []model.BlacklistEntry, now time.Time) {
	if s.Blacklist == nil || len(entries) == 0 {
		return
	}
	batch := make(map[string]time.Duration, len(entries))
	for _, entry := range entries {
		ttl := entry.ExpiresAt.Sub(now)
		if ttl <= 0 {
			continue
		}
		batch[entry.TokenID] = ttl
	}
	if len(batch) == 0 {
		return
	}
	if err := s.Blacklist.BlacklistJTIBatch(ctx, batch); err != nil {
		slog.WarnContext(ctx, "deliver client revocation blacklist", "error", err)
	}
}

func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
