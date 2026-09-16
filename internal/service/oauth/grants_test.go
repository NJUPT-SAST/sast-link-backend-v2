package oauth

import (
	"context"
	"testing"
	"time"
)

// A grant revocation is the one OAuth audit event whose subject and actor are
// different clients: the row is *about* the application being cut off, but it was
// *authorized by* the client the signed-in user is holding. Every other endpoint in
// this package is client-addressed, so `audit` aliases the two — this test is what
// keeps RevokeGrant from being folded back into that shortcut, which would credit
// the revoked application with revoking itself.
func TestRevokeGrantAuditSeparatesActorFromSubject(t *testing.T) {
	h := newHarness(t)

	if err := h.service.RevokeGrant(context.Background(), 7, 42, "sast-link-web"); err != nil {
		t.Fatalf("RevokeGrant() error = %v", err)
	}

	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	entry := h.audit.entries[0]
	if entry.Action != "oauth_grant_revoke" {
		t.Errorf("action = %q, want oauth_grant_revoke", entry.Action)
	}
	if entry.UserID == nil || *entry.UserID != 7 {
		t.Errorf("user id = %v, want 7", entry.UserID)
	}
	if entry.ResourceID == nil || *entry.ResourceID != "42" {
		t.Errorf("resource id = %v, want the revoked client's key 42", entry.ResourceID)
	}
	if entry.ActorClientID == nil || *entry.ActorClientID != "sast-link-web" {
		t.Errorf("actor = %v, want the caller's azp sast-link-web", entry.ActorClientID)
	}
}

// An absent azp must stay NULL rather than become an empty string: V007 reads NULL
// as "no OAuth credential authorized this", and an empty string is neither that nor
// a client id.
func TestRevokeGrantLeavesUnknownActorNull(t *testing.T) {
	h := newHarness(t)

	if err := h.service.RevokeGrant(context.Background(), 7, 42, "  "); err != nil {
		t.Fatalf("RevokeGrant() error = %v", err)
	}

	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	if actor := h.audit.entries[0].ActorClientID; actor != nil {
		t.Errorf("actor = %q, want nil", *actor)
	}
}

// The grants list and revoke are per-user budgeted under separate keys, so
// opening the list cannot exhaust the budget the destructive revoke needs.
func TestGrantsThrottlesByUser(t *testing.T) {
	h := newHarness(t)
	h.limiter.result = LimitResult{Allowed: false, RetryAfter: 30 * time.Second}

	_, err := h.service.Grants(context.Background(), 1)
	oauthErr := oauthError(t, err, ErrorTemporarilyUnavail)
	if oauthErr.Kind != KindRateLimited || oauthErr.RetryAfter != 30*time.Second {
		t.Fatalf("error = %+v, want a rate-limited error carrying Retry-After", oauthErr)
	}
	calls := h.limiter.callsSnapshot()
	if len(calls) != 1 || calls[0] != "oauth_grants_list:user:1" {
		t.Fatalf("limiter calls = %v, want one list keyed by user", calls)
	}
}

// The revoke carries its own budget: a user who burned the list's budget reading
// it can still revoke a misbehaving app.
func TestGrantRevokeThrottlesByUserUnderOwnKey(t *testing.T) {
	h := newHarness(t)
	h.limiter.result = LimitResult{Allowed: false, RetryAfter: 30 * time.Second}

	err := h.service.RevokeGrant(context.Background(), 1, 42, "sast-people")
	oauthErr := oauthError(t, err, ErrorTemporarilyUnavail)
	if oauthErr.Kind != KindRateLimited {
		t.Fatalf("error = %+v, want a rate-limited error", oauthErr)
	}
	calls := h.limiter.callsSnapshot()
	if len(calls) != 1 || calls[0] != "oauth_grants_revoke:user:1" {
		t.Fatalf("limiter calls = %v, want one revoke keyed by user", calls)
	}
}

// A missing dependency is a wiring fault, not an empty list. Answering 200 with
// no grants would report "you have authorized nothing" for a service that cannot
// read the table at all, and the console would look healthy.
func TestGrantsReportsAMissingRepositoryAsInternal(t *testing.T) {
	h := newHarness(t)
	h.service.Authorizations = nil

	_, err := h.service.Grants(context.Background(), 1)
	oauthErr := oauthError(t, err, ErrorServerError)
	if oauthErr.Kind != KindInternal {
		t.Fatalf("Kind = %s, want internal", oauthErr.Kind)
	}
}

// grants is a list field: an empty result must serialize as [] rather than null,
// so no client needs a nil check for the case that carries no information. The
// fake returns a nil slice, which is what a repository with no rows produces.
func TestGrantsReturnsAnEmptySliceNotNull(t *testing.T) {
	h := newHarness(t)

	grants, err := h.service.Grants(context.Background(), 1)
	if err != nil {
		t.Fatalf("Grants() error = %v", err)
	}
	if grants == nil {
		t.Fatal("Grants() = nil, want an empty non-nil slice so the JSON field is [] and not null")
	}
	if len(grants) != 0 {
		t.Fatalf("len(Grants()) = %d, want 0", len(grants))
	}
}

// Same wiring fault as the list: a nil token repository must not read as a
// successful revoke, or the console reports access as cut while every token
// stays live.
func TestRevokeGrantReportsAMissingTokenRepositoryAsInternal(t *testing.T) {
	h := newHarness(t)
	h.service.Tokens = nil

	err := h.service.RevokeGrant(context.Background(), 1, 42, "sast-people")
	oauthErr := oauthError(t, err, ErrorServerError)
	if oauthErr.Kind != KindInternal {
		t.Fatalf("Kind = %s, want internal", oauthErr.Kind)
	}
}
