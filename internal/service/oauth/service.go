package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
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
	// ConsentInfoLimiter throttles the authenticated consent-info peek per user.
	ConsentInfoLimiter EndpointLimiter
	// TokenLimiter throttles the token and revocation endpoints per IP. Both accept
	// client credentials and refresh tokens, so an unlimited rate is an unlimited
	// number of credential attempts and DB round trips.
	TokenLimiter EndpointLimiter
	// ConsentLimiter throttles the authenticated consent submission per user. The
	// peek already has its own budget; the submission mints codes, so it gets a
	// budget of its own rather than sharing the peek's.
	ConsentLimiter EndpointLimiter
	// GrantsLimiter throttles the authorized-apps list and its revoke per user.
	// Both are authenticated and touch only the caller's own grants, but the revoke
	// runs a family-revocation transaction plus a consent-history delete, so it is
	// not free.
	GrantsLimiter EndpointLimiter
	JWT           *auth.JWTManager
	RefreshTokens *auth.RefreshTokenManager
	Clock         Clock
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	// CapabilityRefreshMaxLifetime caps the total life of a refresh family that
	// carries a capability scope (admin/user), measured from the family's origin.
	// A family past the cap is revoked so the client must re-authorize; without it
	// the sliding refresh window renews a delegation forever. Zero disables the cap.
	CapabilityRefreshMaxLifetime time.Duration
	CodeTTL                      time.Duration
	RequestTTL                   time.Duration
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

// capabilityRefreshLifetime returns the total-life cap for a refresh family whose
// scopes carry a capability scope (admin/user), or 0 when it does not (plain OIDC
// families and internal session families keep the uncapped sliding window). The
// cap is measured from the family's origin — its first authorization — so it
// forces a periodic re-authorization instead of a delegation that renews forever.
func (s Service) capabilityRefreshLifetime(scopes []string) time.Duration {
	if s.CapabilityRefreshMaxLifetime <= 0 {
		return 0
	}
	if scope.ContainsAdmin(scopes) || scope.ContainsUser(scopes) {
		return s.CapabilityRefreshMaxLifetime
	}
	return 0
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
	return s.checkLimit(ctx, s.AuthorizeLimiter, "authorize", "ip:"+clientIP)
}

// checkTokenLimit throttles the token and revocation endpoints per caller IP.
//
// Also fail-open, and for the same reason as authorize: PostgreSQL is
// authoritative for every credential these endpoints check, so a lost counter
// only widens the rate window, while refusing every token request during a Redis
// outage would break refresh for every client at once.
//
// The cap is per IP rather than per client_id, because the unauthenticated
// failure modes — guessing a client_secret, replaying refresh tokens — are exactly
// the ones where the client_id is attacker-chosen and therefore worthless as a
// throttling key.
func (s Service) checkTokenLimit(ctx context.Context, clientIP string) error {
	return s.checkLimit(ctx, s.TokenLimiter, "oauth_token", "ip:"+clientIP)
}

// checkConsentInfoLimit throttles the consent-info peek per user. The endpoint is
// authenticated, so it keys on the user rather than the caller IP: campus egress
// shares one NAT IP, and an IP budget would let one student exhaust the whole
// campus's. Same fail-open rationale as the others — a Redis blip must not take
// the consent page down.
func (s Service) checkConsentInfoLimit(ctx context.Context, userID int64) error {
	return s.checkLimit(ctx, s.ConsentInfoLimiter, "consent_info", "user:"+strconv.FormatInt(userID, 10))
}

// checkConsentLimit throttles the consent submission per user, keyed like the peek.
func (s Service) checkConsentLimit(ctx context.Context, userID int64) error {
	return s.checkLimit(ctx, s.ConsentLimiter, "oauth_consent", "user:"+strconv.FormatInt(userID, 10))
}

// checkGrantsListLimit throttles the authorized-apps list per user, for the same
// NAT reason as the consent endpoints: campus egress shares one IP.
func (s Service) checkGrantsListLimit(ctx context.Context, userID int64) error {
	return s.checkLimit(ctx, s.GrantsLimiter, "oauth_grants_list", "user:"+strconv.FormatInt(userID, 10))
}

// checkGrantsRevokeLimit throttles the authorized-apps revoke per user. It gets a
// budget of its own rather than sharing the list's, so opening the list a few
// dozen times cannot exhaust the budget the destructive revoke needs: the one
// action a user may want to take in a hurry is cutting a misbehaving app's access.
func (s Service) checkGrantsRevokeLimit(ctx context.Context, userID int64) error {
	return s.checkLimit(ctx, s.GrantsLimiter, "oauth_grants_revoke", "user:"+strconv.FormatInt(userID, 10))
}

func (s Service) checkLimit(ctx context.Context, limiter EndpointLimiter, endpoint, subject string) error {
	subject = strings.TrimSpace(subject)
	if limiter == nil || subject == "" {
		return nil
	}
	result, err := limiter.Allow(ctx, endpoint, subject)
	if err != nil {
		slog.WarnContext(ctx, "oauth limiter unavailable, allowing request",
			"endpoint", endpoint, "error", err)
		return nil
	}
	if !result.Allowed {
		return withRetryAfter(newError(ErrRateLimited, "请求过于频繁", nil), result.RetryAfter)
	}
	return nil
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
		if entry.ExpiresAt.Sub(now) <= 0 || strings.TrimSpace(entry.TokenID) == "" {
			continue
		}
		jtis = append(jtis, entry.TokenID)
	}
	if len(jtis) == 0 {
		return
	}
	if err := s.Blacklist.DeleteAuthStates(ctx, jtis); err != nil {
		slog.WarnContext(ctx, "invalidate oauth auth-state cache", "count", len(jtis), "error", err)
	}
}

// revokeFamily revokes a token family, discarding the outcome.
//
// For callers where the failure changes no response: a replay defense, whose
// request already fails and whose requester is the suspected attacker, or a
// compensating cleanup that is already returning an error of its own. Propagating
// here would revoke nothing extra — the database is what is unavailable.
//
// A failure is still a security event to alert on rather than noise: until the
// revocation succeeds the suspect family stays valid for up to its full refresh
// TTL. Alert on security_event.
//
// Callers that report the revocation to the requester must use revokeFamilyErr
// instead; answering "revoked" for a revocation that did not happen is worse than
// answering with an error.
func (s Service) revokeFamily(ctx context.Context, familyID string) {
	if err := s.revokeFamilyErr(ctx, familyID); err != nil {
		slog.ErrorContext(ctx, "revoke oauth token family",
			"security_event", "token_family_revocation_failed",
			"family_id", familyID, "error", err)
	}
}

// revokeFamilyErr revokes a token family and delivers its blacklist entries,
// returning whether the revocation actually committed.
//
// It runs on a context detached from the caller: several callers are replay
// defenses, and a client that disconnects right after replaying a code must not be
// able to leave the compromised family alive by hanging up.
func (s Service) revokeFamilyErr(ctx context.Context, familyID string) error {
	if strings.TrimSpace(familyID) == "" {
		return nil
	}
	revokeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationTimeout)
	defer cancel()
	now := s.now()
	entries, err := s.Tokens.RevokeFamily(revokeCtx, familyID, now)
	if err != nil {
		return err
	}
	s.deliverBlacklist(revokeCtx, entries, now)
	return nil
}

// buildAuditEntry materialises the shared oauth audit fields, so the synchronous
// s.audit path and the same-transaction token-rotation audit cannot drift.
//
// actorClientID is passed separately from resourceID rather than aliased onto it.
// On the client-addressed endpoints (authorize / token / revoke) the two are the
// same OAuth client_id, but they answer different questions — resourceID is what
// the action was about, actorClientID is whose credential authorized it — and
// RevokeGrant is the case that separates them: the subject is the client being
// revoked, while the actor is the console client the signed-in user is holding.
func (s Service) buildAuditEntry(
	userID *int64,
	action string,
	resourceID *string,
	actorClientID *string,
	success bool,
	errCode int,
	clientIP, userAgent string,
	detail map[string]any,
) (*model.AuditLog, error) {
	var detailValue model.JSONB
	if detail != nil {
		encoded, err := json.Marshal(detail)
		if err != nil {
			return nil, err
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
	return &model.AuditLog{
		UserID:        userID,
		Action:        action,
		Resource:      "oauth",
		ResourceID:    resourceID,
		ActorClientID: actorClientID,
		Detail:        detailValue,
		ClientIP:      clientIPPtr,
		UserAgent:     userAgentPtr,
		Success:       &successPtr,
		ErrCode:       errCodePtr,
		CreatedAt:     s.now(),
	}, nil
}

// audit records an OAuth event whose subject and actor are the same client, which
// is every client-addressed endpoint. Failures on this detached path are logged,
// never returned: losing an audit row must not fail an otherwise valid
// authorization. The in-transaction audits (authorization-code grant and refresh
// rotation) are the deliberate exception — they ride the token transaction and a
// failure there fails the operation. Use auditAs when they differ.
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
	s.auditAs(ctx, userID, action, resourceID, resourceID, success, errCode, clientIP, userAgent, detail)
}

// auditAs records an OAuth event with an explicit actor, for the paths where the
// client acted upon is not the client that authorized the action.
func (s Service) auditAs(
	ctx context.Context,
	userID *int64,
	action string,
	resourceID *string,
	actorClientID *string,
	success bool,
	errCode int,
	clientIP, userAgent string,
	detail map[string]any,
) {
	if s.Audit == nil {
		return
	}
	entry, err := s.buildAuditEntry(userID, action, resourceID, actorClientID, success, errCode, clientIP, userAgent, detail)
	if err != nil {
		slog.ErrorContext(ctx, "marshal oauth audit detail", "action", action, "error", err)
		return
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
