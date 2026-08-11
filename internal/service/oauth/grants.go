package oauth

import (
	"context"
	"strconv"
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// nullableClientID keeps an absent azp NULL in the audit row instead of writing
// an empty string, which V007 reads as "no OAuth credential authorized this".
func nullableClientID(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
}

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
//
// actorClientID is the client the caller is holding (their token's azp), not the
// client being revoked — the two are different parties here, unlike on the
// client-addressed OAuth endpoints.
func (s Service) RevokeGrant(ctx context.Context, userID, clientID int64, actorClientID string) error {
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
	// resource_id is the primary key of the client whose access was cut, which is
	// all the route carries; actor_client_id is the credential that authorized the
	// cut. An empty azp stays NULL rather than becoming an empty string, matching
	// V007's "no OAuth credential involved" reading.
	clientIDStr := strconv.FormatInt(clientID, 10)
	s.auditAs(ctx, &userID, "oauth_grant_revoke", &clientIDStr,
		nullableClientID(actorClientID), true, 0, "", "", nil)
	return nil
}
