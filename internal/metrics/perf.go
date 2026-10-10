package metrics

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Performance metrics: saturation evidence for the earliest bottlenecks this
// service has (DB pool of maxOpenConns=10, argon2 derivation, synchronous
// external calls with multi-second timeouts). The HTTP latency histogram can
// say "slow"; these attribute the slowness to a resource.
const (
	// Argon2 acquire outcomes.
	Argon2Acquired  = "acquired"
	Argon2Abandoned = "abandoned"

	// GORM operation kinds. Fixed enumeration; statement SQL never reaches a
	// label.
	GormOpQuery = "query"
	GormOpExec  = "exec"
	GormOpRaw   = "raw"

	// Badge render outcomes.
	BadgeRenderHit   = "hit"
	BadgeRenderMiss  = "miss"
	BadgeRenderError = "error"
)

var (
	argon2AcquireTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "argon2_acquire_total",
			Help: "Argon2 derivation-slot acquisitions by result. abandoned means the caller (a login request) gave up waiting: login capacity is saturated.",
		},
		[]string{"result"},
	)

	argon2WaitDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "argon2_wait_duration_seconds",
			Help:    "Time spent waiting for an argon2 derivation slot before acquisition.",
			Buckets: prometheus.ExponentialBuckets(0.005, 2, 14),
		},
	)

	argon2DeriveDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "argon2_derive_duration_seconds",
			Help:    "Argon2id derivation itself (post-slot-acquisition), by operation. The capacity evidence behind KDF parameter decisions.",
			Buckets: prometheus.ExponentialBuckets(0.01, 2, 12),
		},
		[]string{"op"},
	)

	externalRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "external_request_duration_seconds",
			Help:    "Synchronous outbound request latency by dependency and operation. These calls carry 4-6s timeouts and are the tail of this service's own latency.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"dependency", "operation"},
	)

	externalRequestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "external_request_total",
			Help: "Synchronous outbound requests by dependency, operation and result. turnstile's rejected vs unavailable is the 40021-vs-50301 split.",
		},
		[]string{"dependency", "operation", "result"},
	)

	redisCommandDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "redis_command_duration_seconds",
			Help:    "Redis command latency by normalized command name.",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 12),
		},
		[]string{"command"},
	)

	gormQueryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gorm_query_duration_seconds",
			Help:    "GORM statement duration by operation kind.",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
		},
		[]string{"op"},
	)

	gormSlowQueryTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gorm_slow_query_total",
			Help: "GORM statements slower than the slow-query threshold, by operation kind.",
		},
		[]string{"op"},
	)

	badgeRenderDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "badge_render_duration_seconds",
			Help:    "Badge SVG render duration by cache outcome. miss includes the COS avatar fetch and resize.",
			Buckets: prometheus.ExponentialBuckets(0.0025, 2, 12),
		},
		[]string{"result"},
	)

	badgeLaneWaitTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "badge_lane_wait_total",
			Help: "Badge render-lane acquisitions by result. waited growth means render capacity is saturated (the render surface is unauthenticated).",
		},
		[]string{"result"},
	)

	httpInFlight = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_requests_in_flight",
			Help: "Requests currently being served. Rising under flat QPS means a dependency is slowing down.",
		},
	)
)

func init() {
	prometheus.MustRegister(
		argon2AcquireTotal,
		argon2WaitDuration,
		argon2DeriveDuration,
		externalRequestDuration,
		externalRequestTotal,
		redisCommandDuration,
		gormQueryDuration,
		gormSlowQueryTotal,
		badgeRenderDuration,
		badgeLaneWaitTotal,
		httpInFlight,
	)
}

// Argon2 derivation operation labels.
const (
	Argon2OpHash   = "hash"
	Argon2OpVerify = "verify"
	Argon2OpRehash = "rehash"
)

// Argon2Derive observes one derivation's own cost, excluding slot wait.
func Argon2Derive(op string, d time.Duration) {
	argon2DeriveDuration.WithLabelValues(op).Observe(d.Seconds())
}

// Argon2Acquire counts one semaphore acquire attempt. Wait time is observed
// only on success; an abandoned acquire waited at least as long as its context
// allowed, but the exact spend is unknown.
func Argon2Acquire(result string, wait time.Duration) {
	argon2AcquireTotal.WithLabelValues(result).Inc()
	if result == Argon2Acquired {
		argon2WaitDuration.Observe(wait.Seconds())
	}
}

// ExternalRequest records one outbound call: duration always, and the result
// counter carries the outcome the caller maps onto the fixed enumeration
// (empty result skips the counter, for paths where the outcome is not yet
// decided; non-positive duration skips the histogram, for local rejections
// that made no request).
func ExternalRequest(dependency, operation, result string, d time.Duration) {
	if d > 0 {
		externalRequestDuration.WithLabelValues(dependency, operation).Observe(d.Seconds())
	}
	if result != "" {
		externalRequestTotal.WithLabelValues(dependency, operation, result).Inc()
	}
}

// redisKnownCommands is the fixed label set for the command dimension. A
// command outside this set — including anything a future dependency introduces
// — collapses into "other" rather than minting a series, keeping cardinality
// bounded by this list no matter what the code base calls.
var redisKnownCommands = map[string]bool{
	"get": true, "set": true, "del": true, "exists": true, "expire": true,
	"incr": true, "incrby": true, "decr": true, "ttl": true, "pttl": true,
	"eval": true, "evalsha": true, "pipeline": true, "other": true,
}

// NormalizeRedisCommand maps a go-redis FullName onto the fixed command label
// set. FullName is the command verb followed by arguments, so only the first
// word is considered, lower-cased; an unknown or malformed name is "other".
func NormalizeRedisCommand(fullName string) string {
	verb := fullName
	if idx := strings.IndexAny(fullName, " \t"); idx >= 0 {
		verb = fullName[:idx]
	}
	verb = strings.ToLower(strings.TrimSpace(verb))
	if redisKnownCommands[verb] {
		return verb
	}
	return "other"
}

// RedisCommand observes one Redis command. command is the normalized command
// name from Cmder.FullName()'s first word (get, set, del, …), never a key.
func RedisCommand(command string, d time.Duration) {
	redisCommandDuration.WithLabelValues(command).Observe(d.Seconds())
}

// GormQuery observes one statement by operation kind and counts it against the
// slow threshold when it applies. slowThreshold <= 0 disables the slow count.
func GormQuery(op string, d time.Duration, slowThreshold time.Duration) {
	gormQueryDuration.WithLabelValues(op).Observe(d.Seconds())
	if slowThreshold > 0 && d >= slowThreshold {
		gormSlowQueryTotal.WithLabelValues(op).Inc()
	}
}

// BadgeRender observes one render by cache outcome.
func BadgeRender(result string, d time.Duration) {
	badgeRenderDuration.WithLabelValues(result).Observe(d.Seconds())
}

// Badge lane wait outcomes.
const (
	BadgeLaneImmediate = "immediate"
	BadgeLaneWaited    = "waited"
	BadgeLaneRejected  = "rejected"
)

// BadgeLane counts one lane acquire attempt.
func BadgeLane(result string) {
	badgeLaneWaitTotal.WithLabelValues(result).Inc()
}

// HTTPInFlight increments the in-flight gauge and returns the decrement.
// Middleware usage: defer metrics.HTTPInFlight()().
func HTTPInFlight() func() {
	httpInFlight.Inc()
	return httpInFlight.Dec
}
