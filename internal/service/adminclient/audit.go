package adminclient

import "context"

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
func (s Service) auditUpdate(
	ctx context.Context,
	input UpdateClientInput,
	success bool,
	errCode int,
	revokedTokens int,
	clientID *string,
) {
	changed := make([]string, 0, 3)
	if input.ClientName != nil {
		changed = append(changed, "client_name")
	}
	if input.RedirectURIs != nil {
		changed = append(changed, "redirect_uris")
	}
	if input.IsActive != nil {
		changed = append(changed, "is_active")
	}
	detail := map[string]any{"changed_fields": changed}
	if input.IsActive != nil {
		detail["is_active"] = *input.IsActive
	}
	if revokedTokens > 0 {
		detail["revoked_tokens"] = revokedTokens
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
