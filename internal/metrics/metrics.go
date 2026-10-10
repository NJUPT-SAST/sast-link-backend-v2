// Package metrics defines the service's business and performance metrics in
// one place: every metric is registered here on the default Prometheus
// registry (the one /metrics exposes through promhttp), and call sites import
// this package's helpers instead of defining their own collectors. Keeping the
// definitions central bounds what the surface can grow: a new label value is
// a decision made here, next to the others, not something a handler drifts
// into.
//
// Label discipline: every label below is a fixed enumeration owned by this
// package's helpers. No caller-supplied string reaches a label — identifiers,
// paths, email addresses and token values would all mint unbounded cardinality
// (each label set is permanent in Prometheus). This is the same policy
// web/middleware/metrics.go applies to route/method labels.
//
// The helpers are deliberately one line each: the goal is that call sites stay
// readable as instrumentation, not that this package hides the metric.
package metrics

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Fixed label values. Exported so tests and call sites share one spelling;
// re-spelling a value at a call site would silently split the series.
const (
	// Refresh outcome values, shared by the internal-session and OAuth refresh
	// legs. They reuse the audit detail strings (session/service.go's
	// refreshOutcome* constants and oauth/token.go's literals) so a metric
	// alert and an audit row name the same event.
	RefreshOK             = "rotated"
	RefreshReplayed       = "refresh_replayed"
	RefreshConcurrent     = "concurrent_refresh"
	RefreshSessionRevoked = "session_revoked"
	RefreshFamilyExpired  = "refresh_family_expired"

	// Auth-state cache outcomes. miss is the cold-fill path, not an error; the
	// error_* values are the fail-open fallbacks that only log today.
	AuthCacheHit         = "hit"
	AuthCacheMiss        = "miss"
	AuthCacheErrorGet    = "error_get"
	AuthCacheErrorDecode = "error_decode"
	AuthCacheErrorPut    = "error_put"

	// Login failure reasons, matching the audit detail strings. locked and
	// closed are decided before failLogin (checkLoginLock, the state gate) and
	// so are counted at their own branches.
	LoginFailUnknownIdentifier = "identifier_unknown"
	LoginFailBadPassword       = "password_invalid"
	LoginFailLocked            = "locked"
	LoginFailClosed            = "closed"

	// Outbox delivery outcomes.
	OutboxDelivered = "delivered"
	OutboxFailed    = "failed"
	OutboxLeaseLost = "lease_lost"
	OutboxAckShort  = "ack_short"

	// Retention sweep tables. The values are the database table names, matching
	// what sweep's slog rows call the same target.
	RetentionTableAuthorizations = "oauth_authorizations"
	RetentionTableAccessTokens   = "oauth_access_tokens"  // #nosec G101 -- table name, not a credential.
	RetentionTableRefreshTokens  = "oauth_refresh_tokens" // #nosec G101 -- table name, not a credential.
	RetentionTableAuditLogs      = "audit_logs"
	RetentionTableAlumniRequests = "alumni_requests"
	RetentionTableUsersPurged    = "users_purged"

	// Fail-open dependency names. auth_cache is covered by the auth-state
	// cache counters above; these name the remaining fail-open stores.
	FailOpenRateLimit    = "rate_limit"
	FailOpenLoginFailure = "login_failure"
	FailOpenDevice       = "device"

	// SMTP operation names for the external-request metric.
	SMTPSendPlain        = "plain"
	SMTPSendVerifyPrefix = "verify_" // + VerificationPurpose (register/reset_password/bind_email)
	SMTPSendAlumni       = "alumni_result"

	// External dependency and operation names.
	ExtTurnstile      = "turnstile"
	ExtProviderGithub = "provider_github"
	ExtProviderLark   = "provider_lark"
	ExtCOS            = "cos"
	ExtSMTP           = "smtp"

	// External request outcomes. rejected and unavailable are Turnstile's
	// 40021-vs-50301 distinction: rejected means the caller must solve the
	// challenge again, unavailable means verification is not running and the
	// entry point should hide.
	ExtOK          = "ok"
	ExtRejected    = "rejected"
	ExtUnavailable = "unavailable"
	ExtError       = "error"
	ExtTimeout     = "timeout"
)

var (
	refreshOutcomeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_refresh_outcome_total",
			Help: "Refresh-token rotations by path and outcome. refresh_replayed growth means token theft is likely in progress.",
		},
		[]string{"path", "outcome"},
	)

	outboxBacklog = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "token_blacklist_outbox_backlog",
			Help: "Rows awaiting delivery in the token-blacklist outbox. Non-zero growth means revocations are taking effect late.",
		},
	)

	outboxDeliveryTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "token_blacklist_outbox_delivery_total",
			Help: "Token-blacklist outbox delivery attempts by result.",
		},
		[]string{"result"},
	)

	authStateCacheTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_state_cache_total",
			Help: "Auth-state cache lookups by result. error_* values are fail-open fallbacks to PostgreSQL: sustained growth means Redis is down and every authenticated request costs a DB query.",
		},
		[]string{"result"},
	)

	loginFailureTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_login_failure_total",
			Help: "Failed logins by reason. unknown_identifier or bad_password spikes indicate credential stuffing or brute force.",
		},
		[]string{"reason"},
	)

	retentionSweepRows = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "retention_sweep_rows_total",
			Help: "Rows deleted by the retention worker, by table.",
		},
		[]string{"table"},
	)

	retentionTickDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "retention_tick_duration_seconds",
			Help:    "Duration of one retention worker sweep tick.",
			Buckets: prometheus.ExponentialBuckets(0.01, 2, 12),
		},
	)

	retentionLeader = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "retention_leader",
			Help: "1 while this instance holds the retention advisory lock. Exactly one instance across the fleet should be 1; the sum is leader count.",
		},
	)

	redisFailOpenTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "redis_failopen_total",
			Help: "Requests that proceeded without a fail-open Redis dependency (rate limits, login-failure counters, device records). Growth means those guards are silently not enforcing.",
		},
		[]string{"dependency"},
	)

	deviceEvictedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "device_evicted_total",
			Help: "Device records evicted by the 5-device cap. Each eviction revokes a live session family: a spike means more devices than the user owns are active on the account.",
		},
	)

	verificationCodeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "verification_code_total",
			Help: "Email-code verification attempts by purpose and result. The middle of the registration/reset funnel: send volume comes from smtp external metrics, outcomes land here.",
		},
		[]string{"purpose", "result"},
	)

	oauthAuthorizeOutcomeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oauth_authorize_outcome_total",
			Help: "Authorization-code mints by outcome. granted_silent is the standing-grant fast path; its share moving is a registration or grant change, not user behaviour.",
		},
		[]string{"outcome"},
	)

	oauthTokenTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oauth_token_total",
			Help: "Token endpoint requests by grant type and result. Failure detail for refresh lives in auth_refresh_outcome_total.",
		},
		[]string{"grant_type", "result"},
	)

	oauthGrantRevokedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "oauth_grant_revoked_total",
			Help: "Consent grants revoked by users. Each revoke cuts every token the client held, so the client must re-consent.",
		},
	)

	oauthConsentScopeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oauth_consent_scope_total",
			Help: "Scopes consented (or silently re-authorized) per grant. The scope set is the fixed registration catalogue, so cardinality is bounded by it.",
		},
		[]string{"scope", "outcome"},
	)

	httpBusinessCodeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_business_code_total",
			Help: "Envelope business error codes written by response.Error, by code and route. HTTP status alone cannot see a 200 envelope carrying 40108.",
		},
		[]string{"code", "route"},
	)

	oauthCodeOutcomeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oauth_code_outcome_total",
			Help: "Authorization-code redemption outcomes, matching the oauth_token audit detail strings. code_replayed means a single-use code was presented twice: a stolen-code or hijacked redirect_uri signal.",
		},
		[]string{"outcome"},
	)

	authLoginTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_login_total",
			Help: "Successful logins by method. The denominator for auth_login_failure_total. Third-party methods count at login_code issuance (identity verified, session ticket minted), not at exchange-code redemption.",
		},
		[]string{"method"},
	)
)

func init() {
	prometheus.MustRegister(
		refreshOutcomeTotal,
		outboxBacklog,
		outboxDeliveryTotal,
		authStateCacheTotal,
		loginFailureTotal,
		retentionSweepRows,
		retentionTickDuration,
		retentionLeader,
		redisFailOpenTotal,
		deviceEvictedTotal,
		verificationCodeTotal,
		oauthAuthorizeOutcomeTotal,
		oauthTokenTotal,
		oauthGrantRevokedTotal,
		oauthConsentScopeTotal,
		httpBusinessCodeTotal,
		oauthCodeOutcomeTotal,
		authLoginTotal,
	)
	prometheus.MustRegister(newDBPoolCollector())
	prometheus.MustRegister(newRedisPoolCollector())
}

// RefreshOutcome counts one refresh-token rotation outcome. path is "internal"
// (session cookie flow) or "oauth" (provider token endpoint).
func RefreshOutcome(path, outcome string) {
	refreshOutcomeTotal.WithLabelValues(path, outcome).Inc()
}

// Refresh path label values.
const (
	RefreshPathInternal = "internal"
	RefreshPathOAuth    = "oauth"
)

// SetOutboxBacklog records the latest backlog depth. The worker refreshes it
// on its cleanup cadence, so the gauge lags by up to one cleanup interval.
func SetOutboxBacklog(rows float64) {
	outboxBacklog.Set(rows)
}

// OutboxDelivery counts delivery attempts by result. n batches per-entry
// outcomes: a claimed row resolves to exactly one result.
func OutboxDelivery(result string, n int) {
	if n > 0 {
		outboxDeliveryTotal.WithLabelValues(result).Add(float64(n))
	}
}

// AuthStateCache counts one cache lookup result.
func AuthStateCache(result string) {
	authStateCacheTotal.WithLabelValues(result).Inc()
}

// LoginFailure counts one failed login by reason.
func LoginFailure(reason string) {
	loginFailureTotal.WithLabelValues(reason).Inc()
}

// RetentionRows records rows removed from one table in one sweep.
func RetentionRows(table string, rows int64) {
	if rows > 0 {
		retentionSweepRows.WithLabelValues(table).Add(float64(rows))
	}
}

// RetentionTick observes one sweep tick's duration.
func RetentionTick(d time.Duration) {
	retentionTickDuration.Observe(d.Seconds())
}

// SetRetentionLeader marks whether this instance holds the advisory lock.
// Losing the lock must clear the gauge, or the fleet shows two leaders.
func SetRetentionLeader(holds bool) {
	if holds {
		retentionLeader.Set(1)
	} else {
		retentionLeader.Set(0)
	}
}

// RedisFailOpen counts one request that proceeded without a fail-open store.
func RedisFailOpen(dependency string) {
	redisFailOpenTotal.WithLabelValues(dependency).Inc()
}

// DeviceEvicted counts one 5-cap eviction. Counted when the eviction is decided
// (the cap was exceeded), not when the family revoke succeeds — the revoke's
// failure is already logged and retried by the next cap-exceeding login.
func DeviceEvicted() {
	deviceEvictedTotal.Inc()
}

// Verification-code outcomes.
const (
	VerifyCodeOK          = "ok"
	VerifyCodeExpired     = "expired"
	VerifyCodeWrong       = "wrong"
	VerifyCodeUnavailable = "unavailable"
)

// VerificationCode counts one verification attempt by purpose and result.
func VerificationCode(purpose, result string) {
	verificationCodeTotal.WithLabelValues(purpose, result).Inc()
}

// OAuth authorize outcomes, matching the audit decision strings.
const (
	AuthorizeGranted       = "granted"
	AuthorizeGrantedSilent = "granted_silent"
)

// AuthorizeOutcome counts one authorization-code mint path.
func AuthorizeOutcome(outcome string) {
	oauthAuthorizeOutcomeTotal.WithLabelValues(outcome).Inc()
}

// OAuth token grant types and results.
const (
	GrantTypeCode    = "authorization_code"
	GrantTypeRefresh = "refresh_token"
	GrantResultOK    = "ok"
	GrantResultError = "error"
)

// TokenGrant counts one token-endpoint request.
func TokenGrant(grantType, result string) {
	oauthTokenTotal.WithLabelValues(grantType, result).Inc()
}

// GrantRevoked counts one user-initiated consent revoke.
func GrantRevoked() {
	oauthGrantRevokedTotal.Inc()
}

// ConsentScope counts every scope in one consent decision.
func ConsentScope(scopes []string, outcome string) {
	for _, s := range scopes {
		oauthConsentScopeTotal.WithLabelValues(s, outcome).Inc()
	}
}

// BusinessCode counts one envelope business error written to the wire.
func BusinessCode(code int, route string) {
	httpBusinessCodeTotal.WithLabelValues(strconv.Itoa(code), route).Inc()
}

// OAuth code-redemption outcomes, matching the oauth_token audit detail
// strings for the authorization_code grant.
const (
	CodeOutcomeIssued              = "issued"
	CodeOutcomeClientAuthFailed    = "client_auth_failed"
	CodeOutcomeReplayed            = "code_replayed"
	CodeOutcomeRedeemedAfterRevoke = "code_redeemed_after_revocation"
)

// CodeOutcome counts one authorization-code redemption outcome.
func CodeOutcome(outcome string) {
	oauthCodeOutcomeTotal.WithLabelValues(outcome).Inc()
}

// Login method label values. password and register count at the direct session
// mint; github/lark/app_code count at login_code issuance in the callback
// service, where the provider is known (exchange-code cannot see it).
const (
	LoginMethodPassword = "password"
	LoginMethodRegister = "register"
)

// LoginSuccess counts one successful login by method.
func LoginSuccess(method string) {
	authLoginTotal.WithLabelValues(method).Inc()
}
