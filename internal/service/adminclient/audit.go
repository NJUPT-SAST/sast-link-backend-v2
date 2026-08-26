package adminclient

import (
	"context"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

const (
	actionCreateClient = "admin_oauth_client_create"
	actionUpdateClient = "admin_oauth_client_update"
	// #nosec G101 -- G101 matches the "Secret" in the identifier, not a credential:
	// this is the audit action string written to audit_logs.action. The standalone
	// gosec binary in the security workflow and golangci-lint's gosec linter both
	// honour #nosec, so this one directive covers both scanners.
	actionRotateClientSecret = "admin_oauth_client_rotate_secret"
	actionDeleteClient       = "admin_oauth_client_delete"
)

// auditRotateSecret records a secret rotation attempt — refusals included — without
// ever writing the new plaintext. clientID is nil when the target could not be
// resolved (an unknown id).
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

// auditCreate records a registration attempt; the generated client_secret is never
// written to the audit record.
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
	// Capability scopes are flagged from the submitted scopes, so a rejected attempt
	// is marked too.
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

// auditUpdate records an update attempt, naming which fields were touched (names,
// not values). reason is what the update did to the client's granted capability, or
// nil when the request was rejected before the stored row could be compared.
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
	// The capability change is recorded by value, not just name: which scopes a client
	// lost is the question an incident review starts from.
	if reason != nil {
		// Added capability scopes are named by value so the audit says which one was
		// granted; the user scopes get the same treatment.
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
// when an unknown id leaves nothing to name; refusals are recorded too. The
// client_name and capability flags come from that row so an audit reader can still
// see which identifier the client was known by.
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
