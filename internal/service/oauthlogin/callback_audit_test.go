package oauthlogin

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/provider"
)

// lastAuditEntry returns the most recently written audit row.
func lastAuditEntry(t *testing.T, audits *fakeAuditRepository) model.AuditLog {
	t.Helper()
	audits.mu.Lock()
	defer audits.mu.Unlock()
	if len(audits.entries) == 0 {
		t.Fatal("no audit row was written")
	}
	return audits.entries[len(audits.entries)-1]
}

// auditEntries returns a copy of every audit row written so far.
func auditEntries(audits *fakeAuditRepository) []model.AuditLog {
	audits.mu.Lock()
	defer audits.mu.Unlock()
	return append([]model.AuditLog(nil), audits.entries...)
}

// detailString decodes one string field out of an audit row's JSONB detail.
func detailString(t *testing.T, entry model.AuditLog, key string) string {
	t.Helper()
	var detail map[string]any
	if err := json.Unmarshal([]byte(entry.Detail), &detail); err != nil {
		t.Fatalf("decode audit detail %q: %v", entry.Detail, err)
	}
	value, _ := detail[key].(string)
	return value
}

// One business code covers several callback failures, so the audit row has to
// name the step and the cause. Without them a scanner sending no parameters is
// indistinguishable from a replayed state or a provider rejection.
func TestCallbackFailureRecordsStageAndReason(t *testing.T) {
	t.Run("missing code", func(t *testing.T) {
		service, doubles := newTestService(t)
		state, digest := authorizedState(t, service)
		if _, err := service.Callback(context.Background(), CallbackInput{
			Provider: model.LoginMethodGitHub, State: state, StateCookie: digest,
			ClientIP: "203.0.113.9", UserAgent: "curl/8.9.1",
		}); err == nil {
			t.Fatal("Callback() error = nil, want a rejection")
		}
		entry := lastAuditEntry(t, doubles.Audits)
		if got := detailString(t, entry, "failure_stage"); got != StageRequestValidation {
			t.Fatalf("failure_stage = %q, want %q", got, StageRequestValidation)
		}
		if got := detailString(t, entry, "failure_reason"); got != ReasonMissingCode {
			t.Fatalf("failure_reason = %q, want %q", got, ReasonMissingCode)
		}
	})

	t.Run("missing state", func(t *testing.T) {
		service, doubles := newTestService(t)
		if _, err := service.Callback(context.Background(), CallbackInput{
			Provider: model.LoginMethodGitHub, Code: "provider-code",
		}); err == nil {
			t.Fatal("Callback() error = nil, want a rejection")
		}
		entry := lastAuditEntry(t, doubles.Audits)
		if got := detailString(t, entry, "failure_reason"); got != ReasonMissingState {
			t.Fatalf("failure_reason = %q, want %q", got, ReasonMissingState)
		}
	})

	t.Run("state not found", func(t *testing.T) {
		service, doubles := newTestService(t)
		if _, err := service.Callback(context.Background(), CallbackInput{
			Provider: model.LoginMethodGitHub, Code: "provider-code",
			State: "os_never_issued", StateCookie: stateDigest("os_never_issued"),
		}); err == nil {
			t.Fatal("Callback() error = nil, want a rejection")
		}
		entry := lastAuditEntry(t, doubles.Audits)
		if got := detailString(t, entry, "failure_stage"); got != StageState {
			t.Fatalf("failure_stage = %q, want %q", got, StageState)
		}
		if got := detailString(t, entry, "failure_reason"); got != ReasonStateNotFound {
			t.Fatalf("failure_reason = %q, want %q", got, ReasonStateNotFound)
		}
	})

	t.Run("state cookie missing", func(t *testing.T) {
		service, doubles := newTestService(t)
		state, _ := authorizedState(t, service)
		if _, err := service.Callback(context.Background(), CallbackInput{
			Provider: model.LoginMethodGitHub, Code: "provider-code", State: state,
		}); err == nil {
			t.Fatal("Callback() error = nil, want a rejection")
		}
		entry := lastAuditEntry(t, doubles.Audits)
		if got := detailString(t, entry, "failure_reason"); got != ReasonStateCookieMissing {
			t.Fatalf("failure_reason = %q, want %q", got, ReasonStateCookieMissing)
		}
	})

	t.Run("state cookie mismatch", func(t *testing.T) {
		service, doubles := newTestService(t)
		state, _ := authorizedState(t, service)
		if _, err := service.Callback(context.Background(), CallbackInput{
			Provider: model.LoginMethodGitHub, Code: "provider-code",
			State: state, StateCookie: stateDigest("os_someone_elses_state"),
		}); err == nil {
			t.Fatal("Callback() error = nil, want a rejection")
		}
		entry := lastAuditEntry(t, doubles.Audits)
		if got := detailString(t, entry, "failure_reason"); got != ReasonStateCookieMismatch {
			t.Fatalf("failure_reason = %q, want %q", got, ReasonStateCookieMismatch)
		}
	})

	t.Run("provider mismatch", func(t *testing.T) {
		service, doubles := newTestService(t)
		service.Providers[model.LoginMethodLark] = &fakeProvider{
			authorizeURL: "https://lark.test/authorize",
			identity:     &provider.Identity{ProviderID: "on_union", Data: map[string]any{}},
		}
		state, digest := authorizedState(t, service) // issued for github
		if _, err := service.Callback(context.Background(), CallbackInput{
			Provider: model.LoginMethodLark, Code: "provider-code",
			State: state, StateCookie: digest,
		}); err == nil {
			t.Fatal("Callback() error = nil, want a rejection")
		}
		entry := lastAuditEntry(t, doubles.Audits)
		if got := detailString(t, entry, "failure_reason"); got != ReasonProviderMismatch {
			t.Fatalf("failure_reason = %q, want %q", got, ReasonProviderMismatch)
		}
	})

	t.Run("provider invalid grant", func(t *testing.T) {
		service, doubles := newTestService(t)
		doubles.GitHub.err = provider.ErrInvalidGrant
		state, digest := authorizedState(t, service)
		if _, err := service.Callback(context.Background(), CallbackInput{
			Provider: model.LoginMethodGitHub, Code: "spent",
			State: state, StateCookie: digest,
		}); err == nil {
			t.Fatal("Callback() error = nil, want a rejection")
		}
		entry := lastAuditEntry(t, doubles.Audits)
		if got := detailString(t, entry, "failure_stage"); got != StageProvider {
			t.Fatalf("failure_stage = %q, want %q", got, StageProvider)
		}
		if got := detailString(t, entry, "failure_reason"); got != ReasonProviderInvalidGrant {
			t.Fatalf("failure_reason = %q, want %q", got, ReasonProviderInvalidGrant)
		}
	})

	// A success row carries no failure fields, so a query for failures does not
	// have to filter on an empty-string sentinel.
	t.Run("success carries no failure fields", func(t *testing.T) {
		service, doubles := newTestService(t)
		state, digest := authorizedState(t, service)
		if _, err := service.Callback(context.Background(), CallbackInput{
			Provider: model.LoginMethodGitHub, Code: "provider-code",
			State: state, StateCookie: digest,
		}); err != nil {
			t.Fatalf("Callback() error = %v", err)
		}
		entry := lastAuditEntry(t, doubles.Audits)
		if entry.Success == nil || !*entry.Success {
			t.Fatalf("success = %v, want a success row", entry.Success)
		}
		var detail map[string]any
		if err := json.Unmarshal([]byte(entry.Detail), &detail); err != nil {
			t.Fatalf("decode audit detail: %v", err)
		}
		if _, present := detail["failure_reason"]; present {
			t.Fatalf("detail = %v, want no failure_reason on a success row", detail)
		}
	})
}

// The callback is an unauthenticated public endpoint, so its audit rows must not
// claim the built-in console client as the actor: that made anonymous scanner
// traffic look like console activity.
func TestCallbackAuditLeavesActorClientIDNull(t *testing.T) {
	service, doubles := newTestService(t)
	if _, err := service.Callback(context.Background(), CallbackInput{
		Provider: model.LoginMethodGitHub, Code: "provider-code",
		ClientIP: "81.71.101.106", UserAgent: "curl/8.9.1",
	}); err == nil {
		t.Fatal("Callback() error = nil, want a rejection")
	}
	if actor := lastAuditEntry(t, doubles.Audits).ActorClientID; actor != nil {
		t.Fatalf("actor_client_id = %q, want NULL for an unauthenticated callback", *actor)
	}
}

// The login-code exchange happens after the callback, so it is still attributed
// to the built-in client that mints the internal session.
func TestExchangeCodeAuditKeepsInternalActor(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	if err := doubles.LoginCodes.SaveLoginCode(context.Background(), "lc_abc", 42, 0); err != nil {
		t.Fatalf("seed login code: %v", err)
	}
	if _, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "lc_abc"}); err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	entries := auditEntries(doubles.Audits)
	var exchange *model.AuditLog
	for i := range entries {
		if entries[i].Action == "oauth_login_exchange" {
			exchange = &entries[i]
		}
	}
	if exchange == nil {
		t.Fatal("no oauth_login_exchange audit row")
	}
	if exchange.ActorClientID == nil || *exchange.ActorClientID != "sast-link-web" {
		t.Fatalf("actor_client_id = %v, want the built-in client", exchange.ActorClientID)
	}
}

// A deleted account must produce exactly one failure row, carrying the
// provider-side account the tag recorded.
func TestCallbackDeletedUserAuditsOnce(t *testing.T) {
	service, doubles := newTestService(t)
	deleted := activeUser(42)
	deleted.State = model.UserStateDeleted
	doubles.Users.byID[42] = deleted
	doubles.Identities.put(&model.Identity{
		UserID: 42, Provider: model.LoginMethodGitHub, ProviderID: "145339646",
	})
	state, digest := authorizedState(t, service)

	if _, err := service.Callback(context.Background(), CallbackInput{
		Provider: model.LoginMethodGitHub, Code: "provider-code",
		State: state, StateCookie: digest,
	}); err == nil {
		t.Fatal("Callback() error = nil, want a rejection")
	}
	entries := auditEntries(doubles.Audits)
	if len(entries) != 1 {
		t.Fatalf("audit rows = %d, want exactly 1 (the failure must not be double-logged)", len(entries))
	}
	if got := detailString(t, entries[0], "failure_reason"); got != ReasonUserDeleted {
		t.Fatalf("failure_reason = %q, want %q", got, ReasonUserDeleted)
	}
	if got := detailString(t, entries[0], "provider_id"); got != "145339646" {
		t.Fatalf("provider_id = %q, want the provider account the exchange resolved", got)
	}
}

// The callback cap exists to keep an invalid-callback flood from spending state
// and audit writes, so it must run before either.
func TestCallbackLimiterRejectsBeforeStateConsumption(t *testing.T) {
	service, doubles := newTestService(t)
	limiter := &fakeLimiter{result: LimitResult{Allowed: false, RetryAfter: 30 * time.Second}}
	service.CallbackLimiter = limiter

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider: model.LoginMethodGitHub, Code: "provider-code",
		State: "os_whatever", ClientIP: "203.0.113.7",
	})
	assertKind(t, err, KindRateLimited, errcode.CodeRateLimited)
	if got, want := limiter.calls[0], "oauth_login_callback:ip:203.0.113.7"; got != want {
		t.Fatalf("limiter call = %q, want %q", got, want)
	}
	if len(doubles.States.states) != 0 {
		t.Fatal("a throttled callback reached the state store")
	}
	if entries := auditEntries(doubles.Audits); len(entries) != 0 {
		t.Fatalf("audit rows = %d, want none for a throttled request", len(entries))
	}
	if doubles.GitHub.calls != 0 {
		t.Fatal("a throttled callback reached the provider exchange")
	}
}
