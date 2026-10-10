package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// warmup touches every helper once so each vec exposes a series: Prometheus
// vecs report nothing until a label combination is first written, and the
// assertions below are about the exposed families, not the counters' values.
func warmup(t *testing.T) {
	t.Helper()
	RefreshOutcome(RefreshPathInternal, RefreshOK)
	AuthStateCache(AuthCacheMiss)
	LoginFailure(LoginFailBadPassword)
	RedisFailOpen(FailOpenRateLimit)
	OutboxDelivery(OutboxDelivered, 1)
	RetentionRows(RetentionTableAuditLogs, 1)
	RetentionTick(time.Millisecond)
	SetRetentionLeader(false)
	SetOutboxBacklog(0)
	Argon2Acquire(Argon2Acquired, time.Millisecond)
	ExternalRequest(ExtCOS, "upload", ExtOK, time.Millisecond)
	RedisCommand("get", time.Millisecond)
	GormQuery(GormOpQuery, time.Millisecond, 0)
	GormQuery(GormOpRaw, gormSlowThreshold, gormSlowThreshold) // ensure the slow series exists
	BadgeRender(BadgeRenderHit, time.Millisecond)
	BadgeLane(BadgeLaneImmediate)
	HTTPInFlight()()
	DeviceEvicted()
	VerificationCode("register", VerifyCodeOK)
	AuthorizeOutcome(AuthorizeGranted)
	TokenGrant(GrantTypeCode, GrantResultOK)
	GrantRevoked()
	ConsentScope([]string{"openid", "profile"}, AuthorizeGranted)
	BusinessCode(40001, "/user/login")
	Argon2Derive(Argon2OpHash, time.Millisecond)
	CodeOutcome(CodeOutcomeIssued)
	LoginSuccess(LoginMethodPassword)
}

// TestAllFamiliesExposed asserts every metric family in this package is
// registered on the default registry (a duplicate registration would have
// panicked in init) and becomes visible once written.
func TestAllFamiliesExposed(t *testing.T) {
	warmup(t)
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather default registry: %v", err)
	}
	got := map[string]bool{}
	for _, family := range families {
		got[family.GetName()] = true
	}
	want := []string{
		"auth_refresh_outcome_total",
		"token_blacklist_outbox_backlog",
		"token_blacklist_outbox_delivery_total",
		"auth_state_cache_total",
		"auth_login_failure_total",
		"retention_sweep_rows_total",
		"retention_tick_duration_seconds",
		"retention_leader",
		"redis_failopen_total",
		"argon2_acquire_total",
		"argon2_wait_duration_seconds",
		"external_request_duration_seconds",
		"external_request_total",
		"redis_command_duration_seconds",
		"gorm_query_duration_seconds",
		"gorm_slow_query_total",
		"badge_render_duration_seconds",
		"badge_lane_wait_total",
		"http_requests_in_flight",
		"device_evicted_total",
		"verification_code_total",
		"oauth_authorize_outcome_total",
		"oauth_token_total",
		"oauth_grant_revoked_total",
		"oauth_consent_scope_total",
		"http_business_code_total",
		"argon2_derive_duration_seconds",
		"oauth_code_outcome_total",
		"auth_login_total",
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("metric %s missing from default registry", name)
		}
	}
}

// TestPoolCollectorsWithoutSource verifies the collectors emit nothing (rather
// than error) before cmd/api injects the snapshot source.
func TestPoolCollectorsWithoutSource(t *testing.T) {
	registry := prometheus.NewRegistry()
	if err := registry.Register(newDBPoolCollector()); err != nil {
		t.Fatalf("register db pool collector: %v", err)
	}
	if err := registry.Register(newRedisPoolCollector()); err != nil {
		t.Fatalf("register redis pool collector: %v", err)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(families) != 0 {
		t.Fatalf("expected no families without a source, got %d", len(families))
	}
}

// TestDBPoolCollectorWithSource verifies the injected snapshot reaches the
// collector with the right metric types.
func TestDBPoolCollectorWithSource(t *testing.T) {
	SetDBPoolSource(func() DBPoolSnapshot {
		return DBPoolSnapshot{
			MaxOpenConnections: 10,
			OpenConnections:    4,
			InUse:              3,
			Idle:               1,
			WaitCount:          7,
			WaitDuration:       2 * time.Second,
		}
	})
	defer SetDBPoolSource(nil)
	registry := prometheus.NewRegistry()
	if err := registry.Register(newDBPoolCollector()); err != nil {
		t.Fatalf("register: %v", err)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	values := map[string]float64{}
	for _, family := range families {
		for _, m := range family.GetMetric() {
			switch {
			case m.GetGauge() != nil:
				values[family.GetName()] = m.GetGauge().GetValue()
			case m.GetCounter() != nil:
				values[family.GetName()] = m.GetCounter().GetValue()
			}
		}
	}
	want := map[string]float64{
		"db_pool_max_open":              10,
		"db_pool_open":                  4,
		"db_pool_in_use":                3,
		"db_pool_idle":                  1,
		"db_pool_wait_count":            7,
		"db_pool_wait_duration_seconds": 2,
	}
	for name, value := range want {
		if values[name] != value {
			t.Errorf("%s = %v, want %v", name, values[name], value)
		}
	}
}

// TestNormalizeRedisCommand pins the label mapping: known verbs pass through,
// FullName's argument tail is dropped, unknown verbs collapse to "other".
func TestNormalizeRedisCommand(t *testing.T) {
	cases := []struct{ in, want string }{
		{"get", "get"},
		{"get user:42:state", "get"},
		{"SET", "set"},
		{"evalsha abc123 2 k1 k2 argv", "evalsha"},
		{"pipeline", "pipeline"},
		{"eval", "eval"},
		{"lolwut", "other"},
		{"", "other"},
		{"  ", "other"},
	}
	for _, tc := range cases {
		if got := NormalizeRedisCommand(tc.in); got != tc.want {
			t.Errorf("NormalizeRedisCommand(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestGormQuerySlowCounting verifies the slow threshold flips the counter while
// the histogram takes every observation.
func TestGormQuerySlowCounting(t *testing.T) {
	slowBefore := familyOpValue(t, "gorm_slow_query_total", GormOpQuery)
	observedBefore := histogramOpSamples(t, GormOpQuery)
	GormQuery(GormOpQuery, 10*time.Millisecond, 500*time.Millisecond)
	GormQuery(GormOpQuery, 600*time.Millisecond, 500*time.Millisecond)
	GormQuery(GormOpQuery, 600*time.Millisecond, 0) // disabled threshold
	if got := familyOpValue(t, "gorm_slow_query_total", GormOpQuery); got != slowBefore+1 {
		t.Errorf("gorm_slow_query_total op=query = %v, want %v (+1)", got, slowBefore+1)
	}
	if got := histogramOpSamples(t, GormOpQuery); got != observedBefore+3 {
		t.Errorf("gorm_query_duration_seconds op=query samples = %d, want %d (+3)", got, observedBefore+3)
	}
}

func familyOpValue(t *testing.T, familyName, op string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != familyName {
			continue
		}
		for _, m := range family.GetMetric() {
			if metricHasOp(m, op) && m.GetCounter() != nil {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func histogramOpSamples(t *testing.T, op string) uint64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "gorm_query_duration_seconds" {
			continue
		}
		for _, m := range family.GetMetric() {
			if metricHasOp(m, op) && m.GetHistogram() != nil {
				return m.GetHistogram().GetSampleCount()
			}
		}
	}
	return 0
}

func metricHasOp(m *dto.Metric, op string) bool {
	for _, l := range m.GetLabel() {
		if l.GetName() == "op" && l.GetValue() == op {
			return true
		}
	}
	return false
}

// TestExternalRequestLocalRejectionSkipsHistogram verifies a non-positive
// duration (local rejection, no outbound call) counts the outcome without
// polluting the latency histogram.
func TestExternalRequestLocalRejectionSkipsHistogram(t *testing.T) {
	totalBefore := externalTurnstileRejected(t)
	durBefore := externalHistogramSamples(t, ExtTurnstile, "siteverify")
	ExternalRequest(ExtTurnstile, "siteverify", ExtRejected, 0)
	if got := externalTurnstileRejected(t); got != totalBefore+1 {
		t.Errorf("external_request_total{rejected} = %v, want %v (+1)", got, totalBefore+1)
	}
	if got := externalHistogramSamples(t, ExtTurnstile, "siteverify"); got != durBefore {
		t.Errorf("histogram samples grew on local rejection: %d -> %d", durBefore, got)
	}
}

func externalTurnstileRejected(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "external_request_total" {
			continue
		}
		for _, m := range family.GetMetric() {
			dep, res := "", ""
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "dependency":
					dep = l.GetValue()
				case "result":
					res = l.GetValue()
				}
			}
			if dep == ExtTurnstile && res == ExtRejected && m.GetCounter() != nil {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func externalHistogramSamples(t *testing.T, dependency, operation string) uint64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "external_request_duration_seconds" {
			continue
		}
		for _, m := range family.GetMetric() {
			dep, op := "", ""
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "dependency":
					dep = l.GetValue()
				case "operation":
					op = l.GetValue()
				}
			}
			if dep == dependency && op == operation && m.GetHistogram() != nil {
				return m.GetHistogram().GetSampleCount()
			}
		}
	}
	return 0
}

// TestArgon2AbandonedSkipsWaitHistogram verifies an abandoned acquire (unknown
// wait spend) does not observe the wait histogram: only successful acquisitions
// carry a meaningful duration.
func TestArgon2AbandonedSkipsWaitHistogram(t *testing.T) {
	before := argon2WaitSamples(t)
	Argon2Acquire(Argon2Abandoned, 5*time.Second)
	if after := argon2WaitSamples(t); after != before {
		t.Errorf("abandoned acquire observed wait histogram: %d -> %d", before, after)
	}
}

func argon2WaitSamples(t *testing.T) uint64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() == "argon2_wait_duration_seconds" {
			if len(family.GetMetric()) == 0 {
				return 0
			}
			return family.GetMetric()[0].GetHistogram().GetSampleCount()
		}
	}
	return 0
}

// TestOutboxDeliveryZeroIsNoop verifies a zero-count batch writes nothing: the
// helper must not mint empty series.
func TestOutboxDeliveryZeroIsNoop(t *testing.T) {
	OutboxDelivery(OutboxFailed, 1) // ensure the series exists
	before := familyResultValue(t, "token_blacklist_outbox_delivery_total", OutboxFailed)
	OutboxDelivery(OutboxFailed, 0)
	if after := familyResultValue(t, "token_blacklist_outbox_delivery_total", OutboxFailed); after != before {
		t.Errorf("zero batch changed counter: %v -> %v", before, after)
	}
}

func familyResultValue(t *testing.T, familyName, result string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != familyName {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "result" && l.GetValue() == result {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}
