package adminclient

import (
	"context"
	"encoding/json"
	"log/slog"
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
