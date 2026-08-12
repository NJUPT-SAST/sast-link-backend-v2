package adminclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// The built-in client is the one registration this service cannot afford to lose:
// session.findInternalClient resolves it by client_id, so deleting it is an
// unrecoverable lockout for the whole site. The refusal applies to the console
// actor exactly as to a delegate.
func TestDeleteClientRefusesBuiltInClient(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = protectedClient(7)

	_, err := h.service.DeleteClient(context.Background(), DeleteClientInput{ClientPK: 7, AdminUserID: 99})
	assertKind(t, err, KindProtected)
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	entry := h.audit.entries[0]
	if entry.Success == nil || *entry.Success {
		t.Fatalf("audit success = %v, want false", derefBool(entry.Success))
	}
	if entry.Action != actionDeleteClient {
		t.Fatalf("audit action = %q, want %q", entry.Action, actionDeleteClient)
	}
	if entry.ResourceID == nil || *entry.ResourceID != testProtectedClientID {
		t.Fatalf("audit resource_id = %v, want %q", entry.ResourceID, testProtectedClientID)
	}
	if h.clients.deleteCalls != 0 {
		t.Fatalf("DeleteAndRevoke called %d times on a refusal, want 0", h.clients.deleteCalls)
	}
}

// An unknown id cannot name a resource, but the probe itself is worth finding in
// an incident review, so it is audited like every other rejection on this path.
func TestDeleteClientRefusesUnknownID(t *testing.T) {
	h := newHarness(t)

	_, err := h.service.DeleteClient(context.Background(), DeleteClientInput{ClientPK: 999, AdminUserID: 99})
	assertKind(t, err, KindNotFound)
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	entry := h.audit.entries[0]
	if entry.Success == nil || *entry.Success {
		t.Fatalf("audit success = %v, want false", derefBool(entry.Success))
	}
	if entry.Action != actionDeleteClient {
		t.Fatalf("audit action = %q, want %q", entry.Action, actionDeleteClient)
	}
	if entry.ResourceID != nil {
		t.Fatalf("audit resource_id = %v, want nil for an unresolvable target", *entry.ResourceID)
	}
}

// Deleting cuts every token the client held: the still-live access JTIs are
// enqueued for blacklist delivery (delivered to the auth-state cache), the
// revocation count is reported, and the audit names the deregistered client and
// how many tokens it cost.
func TestDeleteClientDeletesAndDeliversBlacklist(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = delegatedClient(5)
	h.clients.deleteEntries = []model.BlacklistEntry{
		{TokenID: "jti-abc", ExpiresAt: testNow.Add(time.Hour)},
		{TokenID: "jti-def", ExpiresAt: testNow.Add(2 * time.Hour)},
	}

	result, err := h.service.DeleteClient(context.Background(), DeleteClientInput{
		ClientPK: 5, AdminUserID: 99,
		ClientIP: "203.0.113.7", UserAgent: "console",
	})
	if err != nil {
		t.Fatalf("DeleteClient() error = %v, want nil", err)
	}
	if result.RevokedTokens != 2 {
		t.Fatalf("RevokedTokens = %d, want 2", result.RevokedTokens)
	}
	if h.clients.deleteID != 5 {
		t.Fatalf("DeleteAndRevoke id = %d, want 5", h.clients.deleteID)
	}
	if len(h.blacklist.jtis) != 2 || h.blacklist.jtis[0] != "jti-abc" || h.blacklist.jtis[1] != "jti-def" {
		t.Fatalf("auth-state cache invalidation jtis = %v, want [jti-abc jti-def]", h.blacklist.jtis)
	}
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	entry := h.audit.entries[0]
	if entry.Success == nil || !*entry.Success {
		t.Fatalf("audit success = %v, want true", derefBool(entry.Success))
	}
	if entry.Action != actionDeleteClient {
		t.Fatalf("audit action = %q, want %q", entry.Action, actionDeleteClient)
	}
	if entry.ResourceID == nil || *entry.ResourceID != "some-ops-tool" {
		t.Fatalf("audit resource_id = %v, want the deregistered client_id", entry.ResourceID)
	}
	detail := decodeAuditDetail(t, entry)
	if detail["client_name"] != "Existing" {
		t.Fatalf("audit detail client_name = %v, want %q", detail["client_name"], "Existing")
	}
	if detail["admin_scope"] != true {
		t.Fatalf("audit detail admin_scope = %v, want true", detail["admin_scope"])
	}
	if detail["revoked_tokens"] != float64(2) {
		t.Fatalf("audit detail revoked_tokens = %v, want 2", detail["revoked_tokens"])
	}
}

// The one capability guard this service does NOT apply: deleting a capability
// client is not console-gated, because deleting removes the credential and the
// scope it carried. A delegated administrator may deregister another client.
func TestDeleteClientDelegatedActorCanDeleteCapabilityClient(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = delegatedClient(5)

	result, err := h.service.DeleteClient(context.Background(), DeleteClientInput{
		ClientPK: 5, AdminUserID: 99,
		ActorClientID: "delegated-ops-tool",
	})
	if err != nil {
		t.Fatalf("DeleteClient() error = %v, want nil for a delegated actor", err)
	}
	if result == nil {
		t.Fatal("DeleteClient() result = nil, want a result")
	}
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	if entry := h.audit.entries[0]; entry.ActorClientID == nil || *entry.ActorClientID != "delegated-ops-tool" {
		t.Fatalf("audit actor_client_id = %v, want the delegated actor", entry.ActorClientID)
	}
	if h.clients.deleteCalls != 1 {
		t.Fatalf("DeleteAndRevoke called %d times, want 1", h.clients.deleteCalls)
	}
}

func derefBool(value *bool) bool {
	if value == nil {
		return false
	}
	return *value
}

// A client whose access tokens have all expired but still holds a live refresh
// session is cut just the same, so the revocation count must include the refresh
// family — otherwise the console would read "0 tokens revoked" for a deletion
// that killed a session.
func TestDeleteClientReportsRefreshOnlyRevocation(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = delegatedClient(5)
	h.clients.deleteRefresh = 1

	result, err := h.service.DeleteClient(context.Background(), DeleteClientInput{ClientPK: 5, AdminUserID: 99})
	if err != nil {
		t.Fatalf("DeleteClient() error = %v, want nil", err)
	}
	if result.RevokedTokens != 1 {
		t.Fatalf("RevokedTokens = %d, want 1 (the revoked refresh session)", result.RevokedTokens)
	}
	// No live access token means nothing to invalidate in the auth-state cache.
	if len(h.blacklist.jtis) != 0 {
		t.Fatalf("auth-state cache invalidation jtis = %v, want empty", h.blacklist.jtis)
	}
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	entry := h.audit.entries[0]
	if entry.Success == nil || !*entry.Success {
		t.Fatalf("audit success = %v, want true", derefBool(entry.Success))
	}
	detail := decodeAuditDetail(t, entry)
	if detail["revoked_tokens"] != float64(1) {
		t.Fatalf("audit detail revoked_tokens = %v, want 1", detail["revoked_tokens"])
	}
}

// A write failure must not look like a deletion: the client still exists, so the
// audit records the attempt as failed and nothing reaches the auth-state cache.
func TestDeleteClientFailedDeleteAuditsInternal(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = delegatedClient(5)
	h.clients.deleteErr = errors.New("db down")

	_, err := h.service.DeleteClient(context.Background(), DeleteClientInput{ClientPK: 5, AdminUserID: 99})
	assertKind(t, err, KindInternal)
	if h.clients.deleteCalls != 1 {
		t.Fatalf("DeleteAndRevoke called %d times, want 1", h.clients.deleteCalls)
	}
	if h.blacklist.jtis != nil {
		t.Fatalf("auth-state cache invalidated on a failed delete: %v", h.blacklist.jtis)
	}
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	entry := h.audit.entries[0]
	if entry.Success == nil || *entry.Success {
		t.Fatalf("audit success = %v, want false", derefBool(entry.Success))
	}
	if entry.Action != actionDeleteClient {
		t.Fatalf("audit action = %q, want %q", entry.Action, actionDeleteClient)
	}
	if entry.ResourceID == nil || *entry.ResourceID != "some-ops-tool" {
		t.Fatalf("audit resource_id = %v, want the resolved client_id", entry.ResourceID)
	}
}

// The HTTP layer's parsePositiveID intercepts a non-positive id, but a direct
// service caller can still reach the guard — and the refusal is audited too, so
// the path stays uniform.
func TestDeleteClientRefusesNonPositivePK(t *testing.T) {
	h := newHarness(t)

	_, err := h.service.DeleteClient(context.Background(), DeleteClientInput{ClientPK: 0, AdminUserID: 99})
	assertKind(t, err, KindNotFound)
	if h.clients.deleteCalls != 0 {
		t.Fatalf("DeleteAndRevoke called %d times on a non-positive id, want 0", h.clients.deleteCalls)
	}
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	if entry := h.audit.entries[0]; entry.Success == nil || *entry.Success {
		t.Fatalf("audit success = %v, want false", derefBool(entry.Success))
	}
}

// A revocation entry whose token has already expired needs no auth-state cache
// invalidation: the middleware would reject it via the DB anyway. The service
// skips it rather than deliver a pointless tombstone.
func TestDeleteClientSkipsExpiredBlacklistEntries(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = delegatedClient(5)
	h.clients.deleteEntries = []model.BlacklistEntry{
		{TokenID: "jti-live", ExpiresAt: testNow.Add(time.Hour)},
		{TokenID: "jti-expired", ExpiresAt: testNow.Add(-time.Minute)},
	}

	result, err := h.service.DeleteClient(context.Background(), DeleteClientInput{ClientPK: 5, AdminUserID: 99})
	if err != nil {
		t.Fatalf("DeleteClient() error = %v, want nil", err)
	}
	if result.RevokedTokens != 2 {
		t.Fatalf("RevokedTokens = %d, want 2 (both tokens revoked)", result.RevokedTokens)
	}
	if len(h.blacklist.jtis) != 1 || h.blacklist.jtis[0] != "jti-live" {
		t.Fatalf("auth-state cache invalidation jtis = %v, want only the still-live token", h.blacklist.jtis)
	}
}

// The blacklist delivery is an optional dependency: a nil Blacklist must not
// panic the deletion path, matching every other fail-open cache in the service.
func TestDeleteClientWithoutBlacklistDoesNotPanic(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = delegatedClient(5)
	h.clients.deleteEntries = []model.BlacklistEntry{{TokenID: "jti-x", ExpiresAt: testNow.Add(time.Hour)}}
	h.service.Blacklist = nil

	result, err := h.service.DeleteClient(context.Background(), DeleteClientInput{ClientPK: 5, AdminUserID: 99})
	if err != nil {
		t.Fatalf("DeleteClient() error = %v, want nil with a nil Blacklist", err)
	}
	if result.RevokedTokens != 1 {
		t.Fatalf("RevokedTokens = %d, want 1", result.RevokedTokens)
	}
}
