package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/tokenissue"
)

const (
	defaultAccessTTL         = time.Hour
	defaultRefreshTTL        = 30 * 24 * time.Hour
	defaultCodeTTL           = 5 * time.Minute
	defaultRequestTTL        = 10 * time.Minute
	authorizationCodePrefix  = "ac_"
	authorizeRequestIDPrefix = "ar_"
	// revocationTimeout bounds the compensating revocation of a replayed family,
	// which must not be abandoned just because the caller disconnected.
	revocationTimeout = 5 * time.Second
)

// Service implements the OAuth 2.1 authorization server and OIDC Provider.
type Service struct {
	Users          UserRepository
	Clients        ClientRepository
	Authorizations AuthorizationRepository
	Tokens         TokenRepository
	Audit          AuditRepository
	Profiles       ProfileRepository
	Requests       AuthorizeRequestStore
	Blacklist      TokenBlacklist
	// AuthorizeLimiter throttles the unauthenticated authorize endpoint per IP.
	AuthorizeLimiter EndpointLimiter
	JWT              *auth.JWTManager
	RefreshTokens    *auth.RefreshTokenManager
	Clock            Clock
	AccessTTL        time.Duration
	RefreshTTL       time.Duration
	CodeTTL          time.Duration
	RequestTTL       time.Duration
	// CardBaseURL prefixes the OIDC profile claim; a user's card lives at
	// CardBaseURL + "/" + user ID.
	CardBaseURL string
	// Issuer is the OIDC issuer identifier and the base for discovery endpoints.
	Issuer string
}

func (s Service) now() time.Time {
	clock := s.Clock
	if clock == nil {
		clock = auth.SystemClock
	}
	return clock.Now().UTC()
}

func (s Service) accessTTL() time.Duration {
	if s.AccessTTL > 0 {
		return s.AccessTTL
	}
	return defaultAccessTTL
}

func (s Service) refreshTTL() time.Duration {
	if s.RefreshTTL > 0 {
		return s.RefreshTTL
	}
	return defaultRefreshTTL
}

func (s Service) codeTTL() time.Duration {
	if s.CodeTTL > 0 {
		return s.CodeTTL
	}
	return defaultCodeTTL
}

func (s Service) requestTTL() time.Duration {
	if s.RequestTTL > 0 {
		return s.RequestTTL
	}
	return defaultRequestTTL
}

// issuer returns the token issuer shared with the internal session service, so
// both paths produce identical token metadata.
func (s Service) issuer() tokenissue.Issuer {
	return tokenissue.Issuer{JWT: s.JWT, Refresh: s.RefreshTokens, Clock: s.Clock}
}

// checkAuthorizeLimit throttles the authorize endpoint. Fail-open per PRD §6.0:
// the limiter guards against stash flooding, and refusing every authorization
// during a Redis blip would take third-party login down entirely.
func (s Service) checkAuthorizeLimit(ctx context.Context, clientIP string) error {
	subject := strings.TrimSpace(clientIP)
	if s.AuthorizeLimiter == nil || subject == "" {
		return nil
	}
	result, err := s.AuthorizeLimiter.Allow(ctx, "authorize", "ip:"+subject)
	if err != nil {
		slog.WarnContext(ctx, "authorize limiter unavailable, allowing request", "error", err)
		return nil
	}
	if !result.Allowed {
		return withRetryAfter(newError(ErrRateLimited, "请求过于频繁", nil), result.RetryAfter)
	}
	return nil
}

// deliverBlacklist attempts a synchronous Redis delivery of revoked JTIs. The
// durable outbox row was already written in the revoking transaction, so a
// failure here only delays the fast-reject path; the auth middleware's DB check
// rejects these tokens either way.
func (s Service) deliverBlacklist(ctx context.Context, entries []model.BlacklistEntry, now time.Time) {
	if s.Blacklist == nil || len(entries) == 0 {
		return
	}
	batch := make(map[string]time.Duration, len(entries))
	for _, entry := range entries {
		ttl := entry.ExpiresAt.Sub(now)
		if ttl <= 0 || strings.TrimSpace(entry.TokenID) == "" {
			continue
		}
		batch[entry.TokenID] = ttl
	}
	if len(batch) == 0 {
		return
	}
	if err := s.Blacklist.BlacklistJTIBatch(ctx, batch); err != nil {
		slog.WarnContext(ctx, "oauth blacklist delivery unavailable", "count", len(batch), "error", err)
	}
}

// revokeFamily revokes a token family and delivers its blacklist entries.
//
// It runs on a context detached from the caller: the two callers are replay
// defenses, and a client that disconnects right after replaying a code must not
// be able to leave the compromised family alive by hanging up.
func (s Service) revokeFamily(ctx context.Context, familyID string) {
	if strings.TrimSpace(familyID) == "" {
		return
	}
	revokeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationTimeout)
	defer cancel()
	now := s.now()
	entries, err := s.Tokens.RevokeFamily(revokeCtx, familyID, now)
	if err != nil {
		slog.ErrorContext(revokeCtx, "revoke oauth token family", "family_id", familyID, "error", err)
		return
	}
	s.deliverBlacklist(revokeCtx, entries, now)
}

// audit records an OAuth audit event. Audit failures are logged, never returned:
// losing an audit row must not fail an otherwise valid authorization.
func (s Service) audit(
	ctx context.Context,
	userID *int64,
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
	var detailValue model.JSONB
	if detail != nil {
		encoded, err := json.Marshal(detail)
		if err != nil {
			slog.ErrorContext(ctx, "marshal oauth audit detail", "action", action, "error", err)
			return
		}
		detailValue = model.JSONB(encoded)
	}
	var errCodePtr *int
	if errCode != 0 {
		errCodePtr = &errCode
	}
	var clientIPPtr *string
	if strings.TrimSpace(clientIP) != "" {
		clientIPPtr = &clientIP
	}
	var userAgentPtr *string
	if strings.TrimSpace(userAgent) != "" {
		userAgentPtr = &userAgent
	}
	successPtr := success
	entry := &model.AuditLog{
		UserID:     userID,
		Action:     action,
		Resource:   "oauth",
		ResourceID: resourceID,
		Detail:     detailValue,
		ClientIP:   clientIPPtr,
		UserAgent:  userAgentPtr,
		Success:    &successPtr,
		ErrCode:    errCodePtr,
		CreatedAt:  s.now(),
	}
	// Detached like the revocation above: an audit row for a completed action must
	// survive the caller going away, or the log would silently lose exactly the
	// events an aborted request produced.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationTimeout)
	defer cancel()
	if err := s.Audit.Create(auditCtx, entry); err != nil {
		slog.ErrorContext(auditCtx, "audit oauth event", "action", action, "error", err)
	}
}

func newAuthorizationCode() (string, error) {
	return randomToken(authorizationCodePrefix, 32)
}

func newAuthorizeRequestID() (string, error) {
	return randomToken(authorizeRequestIDPrefix, 16)
}

func randomToken(prefix string, size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate %s token: %w", strings.TrimSuffix(prefix, "_"), err)
	}
	return prefix + hex.EncodeToString(raw), nil
}
