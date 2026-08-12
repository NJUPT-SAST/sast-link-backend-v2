package adminclient

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

// A failed write must not surface the computed capability change as if it
// persisted: an audit row claiming scopes_removed for an update that never hit
// the database reads as a revocation that did not happen.
func TestUpdateClientFailedWriteOmitsCapabilityChangeFromAudit(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = delegatedClient(5)
	h.clients.updateErr = errors.New("db down")
	narrowed := []string{"openid"}

	_, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
		ClientPK:      5,
		Scope:         &narrowed,
		AdminUserID:   99,
		ActorClientID: "",
	})
	if err == nil {
		t.Fatal("UpdateClient() error = nil, want an error from the failed write")
	}
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	entry := h.audit.entries[0]
	if entry.Success == nil || *entry.Success {
		t.Fatalf("audit success = %v, want false", entry.Success)
	}
	detail := decodeAuditDetail(t, entry)
	if _, ok := detail["scopes_removed"]; ok {
		t.Fatalf("audit detail contains scopes_removed for a write that never persisted: %v", detail)
	}
	if _, ok := detail["admin_scope_revoked"]; ok {
		t.Fatalf("audit detail contains admin_scope_revoked for a write that never persisted: %v", detail)
	}
}

// Promoting a client from user:read to user:write mirrors the admin promotion: a
// real capability is added, and the audit must name the added scope rather than
// report a boolean the already-scoped client would have missed.
func TestUpdateClientPromotionAuditNamesAddedUserScope(t *testing.T) {
	h := newHarness(t)
	current := activeClient(5)
	current.Scopes = model.StringArray{"openid", scope.UserRead}
	h.clients.findResult = current
	promoted := []string{"openid", scope.UserRead, scope.UserWrite}

	if _, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
		ClientPK:      5,
		Scope:         &promoted,
		AdminUserID:   99,
		ActorClientID: "",
	}); err != nil {
		t.Fatalf("UpdateClient() error = %v", err)
	}
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	detail := decodeAuditDetail(t, h.audit.entries[0])
	granted, ok := detail["user_scope_granted"]
	if !ok {
		t.Fatalf("audit detail missing user_scope_granted for the promotion: %v", detail)
	}
	got, ok := granted.([]any)
	if !ok {
		t.Fatalf("user_scope_granted = %#v (%T), want a list of scope names", granted, granted)
	}
	if len(got) != 1 || got[0] != scope.UserWrite {
		t.Fatalf("user_scope_granted = %v, want [%s]", got, scope.UserWrite)
	}
}

func TestUpdateClientPromotionAuditNamesAddedAdminScope(t *testing.T) {
	h := newHarness(t)
	current := activeClient(5)
	current.Scopes = model.StringArray{"openid", scope.AdminRead}
	h.clients.findResult = current
	promoted := []string{"openid", scope.AdminRead, scope.AdminWrite}

	if _, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
		ClientPK:      5,
		Scope:         &promoted,
		AdminUserID:   99,
		ActorClientID: "",
	}); err != nil {
		t.Fatalf("UpdateClient() error = %v", err)
	}
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	detail := decodeAuditDetail(t, h.audit.entries[0])
	granted, ok := detail["admin_scope_granted"]
	if !ok {
		t.Fatalf("audit detail missing admin_scope_granted for the promotion: %v", detail)
	}
	got, ok := granted.([]any)
	if !ok {
		t.Fatalf("admin_scope_granted = %#v (%T), want a list of scope names", granted, granted)
	}
	if len(got) != 1 || got[0] != scope.AdminWrite {
		t.Fatalf("admin_scope_granted = %v, want [%s]", got, scope.AdminWrite)
	}
}

func decodeAuditDetail(t *testing.T, entry *model.AuditLog) map[string]any {
	t.Helper()
	detail := map[string]any{}
	if len(entry.Detail) == 0 {
		return detail
	}
	if err := json.Unmarshal([]byte(entry.Detail), &detail); err != nil {
		t.Fatalf("decode audit detail: %v", err)
	}
	return detail
}
