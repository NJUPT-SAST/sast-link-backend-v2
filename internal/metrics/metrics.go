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
