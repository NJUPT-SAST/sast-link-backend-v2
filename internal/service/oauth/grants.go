package oauth

import (
	"context"
	"strconv"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// Grants returns the applications the user has authorized via the consent
// screen.
func (s Service) Grants(ctx context.Context, userID int64) ([]repository.OAuthGrant, error) {
	if s.Authorizations == nil {
		return nil, nil
	}
	return s.Authorizations.ListGrantsByUser(ctx, userID)
}

// RevokeGrant removes one application's access for the user: every token they
// hold with that client is revoked, so the client must re-consent on next use.
func (s Service) RevokeGrant(ctx context.Context, userID, clientID int64) error {
	if s.Tokens == nil {
		return nil
	}
	now := s.now()
	entries, err := s.Tokens.RevokeUserClientTokens(ctx, userID, clientID, now)
	if err != nil {
		return err
	}
	s.deliverBlacklist(ctx, entries, now)
	// Drop the consent history too, so the application leaves the authorized list
	// and must re-consent on its next use.
	if s.Authorizations != nil {
		if err := s.Authorizations.DeleteByUserClient(ctx, userID, clientID); err != nil {
			return err
		}
	}
	clientIDStr := strconv.FormatInt(clientID, 10)
	s.audit(ctx, &userID, "oauth_grant_revoke", &clientIDStr, true, 0, "", "", nil)
	return nil
}
