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
}

func (s Service) now() time.Time {
	clock := s.Clock
	if clock == nil {
		clock = auth.SystemClock
	}
	return clock.Now().UTC()
}

// audit records an admin action. Failures are logged, never returned: losing an
// audit row must not fail an otherwise valid change, but it must not pass
// silently either.
func (s Service) audit(
	ctx context.Context,
	adminUserID int64,
	action string,
	targetUserID int64,
	success bool,
	errCode int,
	clientIP, userAgent string,
	detail map[string]any,
) {
	if s.Audit == nil {
		return
	}
	resourceID := strconv.FormatInt(targetUserID, 10)
	entry := &model.AuditLog{
		UserID:     &adminUserID,
		Action:     action,
		Resource:   auditResourceUser,
		ResourceID: &resourceID,
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
			slog.ErrorContext(ctx, "marshal admin user audit detail", "action", action, "error", err)
			return
		}
		entry.Detail = model.JSONB(encoded)
	}
	// Detached like adminclient.Service.audit: an action that already committed
	// (closing an account and revoking its tokens) must still be recorded when the
	// caller goes away, or the audit log loses exactly the events an aborted request
	// produced.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := s.Audit.Create(auditCtx, entry); err != nil {
		slog.ErrorContext(auditCtx, "record admin user audit", "action", action, "error", err)
	}
}

// deliverBlacklist pushes revoked JTIs to the fast-reject cache. The durable
// outbox rows were written in the revoking transaction, so a failure here only
// delays that path; the middleware's DB check rejects these tokens either way.
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
		slog.WarnContext(ctx, "deliver admin user revocation blacklist", "error", err)
	}
}

func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
