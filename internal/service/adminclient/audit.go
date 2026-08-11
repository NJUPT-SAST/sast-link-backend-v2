package adminclient

import (
	"context"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

const (
	actionCreateClient = "admin_oauth_client_create"
	actionUpdateClient = "admin_oauth_client_update"
)

// auditCreate records a registration attempt.
//
// The generated client_secret never appears here. An audit row is long-lived and
// widely readable, so writing the plaintext into it would defeat the point of
// storing only a hash.
func (s Service) auditCreate(
	ctx context.Context,
	input CreateClientInput,
	clientID *string,
	success bool,
	errCode int,
	revokedTokens int,
) {
	detail := map[string]any{
		"client_name": input.ClientName,
		"client_type": input.ClientType,
	}
	// A registration that arrives holding delegated administration is worth finding in
	// the audit log without cross-referencing the row it created. Recorded from the
	// submitted scopes, so a rejected attempt is flagged too.
	if scope.ContainsAdmin(input.Scopes) {
		detail["admin_scope"] = true
	}
	if revokedTokens > 0 {
		detail["revoked_tokens"] = revokedTokens
	}
	s.audit(ctx, auditParams{
		AdminUserID:   input.AdminUserID,
		ActorClientID: input.ActorClientID,
		Action:        actionCreateClient,
		ResourceID:    clientID,
		Success:       success,
		ErrCode:       errCode,
		ClientIP:      input.ClientIP,
		UserAgent:     input.UserAgent,
		Detail:        detail,
	})
}

// auditUpdate records an update attempt, naming which fields were touched.
//
// Field names rather than values: a redirect_uris list is long and the useful
// question after the fact is which properties an administrator changed and whether
// the change cut existing sessions.
// reason is what the update did to the client's granted capability, or nil when the
// request was rejected before the stored row could be compared against it.
func (s Service) auditUpdate(
	ctx context.Context,
	input UpdateClientInput,
	success bool,
	errCode int,
	revokedTokens int,
	clientID *string,
	reason *revocation,
) {
	changed := make([]string, 0, 5)
	if input.ClientName != nil {
		changed = append(changed, "client_name")
	}
	if input.RedirectURIs != nil {
		changed = append(changed, "redirect_uris")
	}
	if input.IsActive != nil {
		changed = append(changed, "is_active")
	}
	// grant_types and scopes were missing here while they were the two fields an
	// administrator could not meaningfully change. They now carry delegated
	// administration, so an audit row that omitted them would lose exactly the events
	// worth reviewing.
	if input.GrantTypes != nil {
		changed = append(changed, "grant_types")
	}
	if input.Scope != nil {
		changed = append(changed, "scopes")
	}
	detail := map[string]any{"changed_fields": changed}
	if input.IsActive != nil {
		detail["is_active"] = *input.IsActive
	}
	if revokedTokens > 0 {
		detail["revoked_tokens"] = revokedTokens
	}
	// Values, not just field names, for the capability change alone: "which scopes did
	// this client stop holding" is the question a review of an administrative incident
	// starts from, and it cannot be answered from a field name plus a later snapshot.
	if reason != nil {
		// The added admin scopes are named by value, not reported as a bare boolean:
		// promoting a client from admin:read to admin:write grants a real capability
		// and the audit must say which one. 0->admin records the full list too, so the
		// field is always a list when present.
		if len(reason.AdminScopesAdded) > 0 {
			detail["admin_scope_granted"] = reason.AdminScopesAdded
		}
		if len(reason.ScopesRemoved) > 0 {
			detail["scopes_removed"] = reason.ScopesRemoved
			if scope.ContainsAdmin(reason.ScopesRemoved) {
				detail["admin_scope_revoked"] = true
			}
		}
	}
	s.audit(ctx, auditParams{
		AdminUserID:   input.AdminUserID,
		ActorClientID: input.ActorClientID,
		Action:        actionUpdateClient,
		ResourceID:    clientID,
		Success:       success,
		ErrCode:       errCode,
		ClientIP:      input.ClientIP,
		UserAgent:     input.UserAgent,
		Detail:        detail,
	})
}
