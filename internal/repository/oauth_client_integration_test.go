package repository_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func TestOAuthClientRepositoryFindActiveByClientID(t *testing.T) {
	database := setupDatabase(t)
	oauthClientRepository := repository.NewOAuthClient(database)

	client, err := oauthClientRepository.FindActiveByClientID(context.Background(), "sast-link-web")
	if err != nil {
		t.Fatalf("FindActiveByClientID(built-in) error = %v", err)
	}
	if client.ClientID != "sast-link-web" || client.ClientName != "SAST Link Web" ||
		client.ClientType != model.ClientTypeFirstParty || client.ClientSecretHash != nil ||
		!reflect.DeepEqual(client.RedirectURIs, model.StringArray{
			"https://link.sast.fun/oauth/callback",
			"http://localhost:3000/oauth/callback",
		}) ||
		!reflect.DeepEqual(client.GrantTypes, model.StringArray{"authorization_code", "refresh_token"}) ||
		!reflect.DeepEqual(client.Scopes, model.StringArray{"openid", "profile", "email"}) ||
		client.IsActive == nil || !*client.IsActive {
		t.Fatalf("FindActiveByClientID(built-in) = %#v, want seeded active first-party public client", client)
	}

	inactive := &model.OAuthClient{
		ClientID:     "inactive-client",
		ClientName:   "Inactive Client",
		ClientType:   model.ClientTypeFirstParty,
		RedirectURIs: model.StringArray{"https://example.test/callback"},
		GrantTypes:   model.StringArray{"authorization_code"},
		Scopes:       model.StringArray{"openid"},
		IsActive:     boolPtr(false),
	}
	createErr := database.Create(inactive).Error
	if createErr != nil {
		t.Fatalf("create inactive OAuth client: %v", createErr)
	}
	for _, clientID := range []string{"inactive-client", "missing-client"} {
		_, findErr := oauthClientRepository.FindActiveByClientID(context.Background(), clientID)
		if !errors.Is(findErr, repository.ErrNotFound) {
			t.Fatalf("FindActiveByClientID(%q) error = %v, want ErrNotFound", clientID, findErr)
		}
	}
	_, emptyErr := oauthClientRepository.FindActiveByClientID(context.Background(), "")
	if !errors.Is(emptyErr, repository.ErrInvalidArgument) {
		t.Fatalf("FindActiveByClientID(empty) error = %v, want ErrInvalidArgument", emptyErr)
	}
}

// FindByID must resolve a deactivated client. Token rows reference this primary
// key, so if deactivation made the owner unresolvable, revoking or auditing a
// disabled client's live tokens would fail instead of reporting the disabled
// state.
