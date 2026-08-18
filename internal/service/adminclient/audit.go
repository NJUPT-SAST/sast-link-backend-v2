package adminclient

import (
	"context"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

const (
	actionCreateClient = "admin_oauth_client_create"
	actionUpdateClient = "admin_oauth_client_update"
	// Both suppressions are needed and neither is redundant: golangci-lint's gosec
	// linter reads //nolint, while the standalone gosec binary in the security
	// workflow only honours #nosec, so dropping either one turns G101 back on in
	// one of the two places. The finding itself is the name: G101 matches the
	// "Secret" in the identifier, and this is the audit action string written to
	// audit_logs.action, not a credential.
	//nolint:gosec // G101 trips on the "Secret" in the name; this is an audit action string, not a credential.
	actionRotateClientSecret = "admin_oauth_client_rotate_secret" // #nosec G101
	actionDeleteClient       = "admin_oauth_client_delete"
)

// auditRotateSecret records a secret rotation attempt. The new plaintext never
// appears here — like auditCreate, only the fact that a rotation was attempted is
// durable. clientID is nil when the target could not be resolved (an unknown id);
// the refusals that precede the write are recorded too, so a leaked-secret
// incident review finds the probes, not just the successful rotations.
func (s Service) auditRotateSecret(ctx context.Context, input RotateClientSecretInput, clientID *string, success bool, errCode int) {
	s.audit(ctx, auditParams{
		AdminUserID:   input.AdminUserID,
		ActorClientID: input.ActorClientID,
		Action:        actionRotateClientSecret,
		ResourceID:    clientID,
		Success:       success,
		ErrCode:       errCode,
		ClientIP:      input.ClientIP,
		UserAgent:     input.UserAgent,
	})
}

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
	// A registration that arrives holding a capability scope is worth finding in the
	// audit log without cross-referencing the row it created. Recorded from the
	// submitted scopes, so a rejected attempt is flagged too.
	if scope.ContainsAdmin(input.Scopes) {
		detail["admin_scope"] = true
	}
	if scope.ContainsUser(input.Scopes) {
		detail["user_scope"] = true
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
		// field is always a list when present. The user scopes get the same treatment
		// for the same reason.
		if len(reason.AdminScopesAdded) > 0 {
			detail["admin_scope_granted"] = reason.AdminScopesAdded
		}
		if len(reason.UserScopesAdded) > 0 {
			detail["user_scope_granted"] = reason.UserScopesAdded
		}
		if len(reason.ScopesRemoved) > 0 {
			detail["scopes_removed"] = reason.ScopesRemoved
			if scope.ContainsAdmin(reason.ScopesRemoved) {
				detail["admin_scope_revoked"] = true
			}
			if scope.ContainsUser(reason.ScopesRemoved) {
				detail["user_scope_revoked"] = true
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

// auditDelete records a deregistration attempt. current is the resolved row, nil
// when the target could not be resolved (an unknown id) and the attempt therefore
// names nothing. The client_name and capability flags come from that row — the
// client_id (ResourceID) survives the row's deletion, so an audit reader tracing a
// deregistration can still see which identifier it was known by. Refusals (the
// built-in client, an unknown id) are recorded too, like every other rejection on
// this service's paths.
func (s Service) auditDelete(
	ctx context.Context,
	input DeleteClientInput,
	current *model.OAuthClient,
	success bool,
	errCode int,
	revokedTokens int,
) {
	detail := map[string]any{}
	if current != nil {
		detail["client_name"] = current.ClientName
		detail["client_type"] = string(current.ClientType)
		if scope.ContainsAdmin([]string(current.Scopes)) {
			detail["admin_scope"] = true
		}
		if scope.ContainsUser([]string(current.Scopes)) {
			detail["user_scope"] = true
		}
	}
	if revokedTokens > 0 {
		detail["revoked_tokens"] = revokedTokens
	}
	var clientID *string
	if current != nil {
		clientID = &current.ClientID
	}
	s.audit(ctx, auditParams{
		AdminUserID:   input.AdminUserID,
		ActorClientID: input.ActorClientID,
		Action:        actionDeleteClient,
		ResourceID:    clientID,
		Success:       success,
		ErrCode:       errCode,
		ClientIP:      input.ClientIP,
		UserAgent:     input.UserAgent,
		Detail:        detail,
	})
}
