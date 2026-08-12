package repository_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

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

// FindByID must resolve a deactivated client: the admin update path reads the
// current row to decide whether is_active is going true -> false, which is what
// triggers revocation, so it has to see disabled rows.
func TestOAuthClientRepositoryFindByIDIgnoresActiveState(t *testing.T) {
	database := setupDatabase(t)
	clients := repository.NewOAuthClient(database)
	client := createOAuthClient(t, database)

	if _, _, err := clients.UpdateAndRevoke(context.Background(), client.ID,
		map[string]any{"is_active": false}, false, time.Now()); err != nil {
		t.Fatalf("UpdateAndRevoke(deactivate) error = %v", err)
	}
	found, err := clients.FindByID(context.Background(), client.ID)
	if err != nil {
		t.Fatalf("FindByID(disabled) error = %v, want the disabled row", err)
	}
	if found.IsActive == nil || *found.IsActive {
		t.Fatalf("FindByID(disabled).IsActive = %v, want false", found.IsActive)
	}
	if _, err := clients.FindByID(context.Background(), 0); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("FindByID(0) error = %v, want ErrInvalidArgument", err)
	}
	if _, err := clients.FindByID(context.Background(), 999999); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindByID(missing) error = %v, want ErrNotFound", err)
	}
}

func TestOAuthClientRepositoryListAndCreate(t *testing.T) {
	database := setupDatabase(t)
	clients := repository.NewOAuthClient(database)

	created := &model.OAuthClient{
		ClientID:     "list-test-client",
		ClientName:   "List Test",
		ClientType:   model.ClientTypeThirdParty,
		RedirectURIs: model.StringArray{"https://app.test/cb"},
		GrantTypes:   model.StringArray{"authorization_code"},
		Scopes:       model.StringArray{"openid"},
	}
	if err := clients.Create(context.Background(), created); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.ID == 0 {
		t.Fatal("Create() did not populate the primary key")
	}

	// Deactivated clients must still be listed, or the console could not re-enable
	// one it had just disabled.
	if _, _, err := clients.UpdateAndRevoke(context.Background(), created.ID,
		map[string]any{"is_active": false}, false, time.Now()); err != nil {
		t.Fatalf("UpdateAndRevoke(deactivate) error = %v", err)
	}
	listed, err := clients.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	var sawBuiltin, sawDisabled bool
	for _, client := range listed {
		switch client.ClientID {
		case "sast-link-web":
			sawBuiltin = true
		case "list-test-client":
			sawDisabled = true
		}
	}
	if !sawBuiltin || !sawDisabled {
		t.Fatalf("List() = %d clients, want the built-in and the disabled one", len(listed))
	}
	if _, _, err := clients.UpdateAndRevoke(context.Background(), 999999,
		map[string]any{"client_name": "x"}, false, time.Now()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("UpdateAndRevoke(missing) error = %v, want ErrNotFound", err)
	}
}

// Disabling a client must revoke exactly its own live tokens, atomically with the
// flag flip, and must not touch another client's tokens for the same user.
func TestOAuthClientRepositoryUpdateAndRevokeIsScopedToOneClient(t *testing.T) {
	database := setupDatabase(t)
	clients := repository.NewOAuthClient(database)
	tokens := repository.NewToken(database)
	users := repository.NewUser(database)
	user := createUserWithProfile(t, users, "revoke-by-client@njupt.edu.cn")

	target := createOAuthClient(t, database)
	other := &model.OAuthClient{
		ClientID:     "bystander-client",
		ClientName:   "Bystander",
		ClientType:   model.ClientTypeThirdParty,
		RedirectURIs: model.StringArray{"https://bystander.test/cb"},
		GrantTypes:   model.StringArray{"authorization_code"},
		Scopes:       model.StringArray{"openid"},
	}
	if err := clients.Create(context.Background(), other); err != nil {
		t.Fatalf("create bystander client: %v", err)
	}

	createTokenPair(t, tokens, "target-a", "family-target-a", 0, target.ID, user.ID)
	createTokenPair(t, tokens, "target-b", "family-target-b", 0, target.ID, user.ID)
	createTokenPair(t, tokens, "bystander", "family-bystander", 0, other.ID, user.ID)

	revokedAt := time.Now().UTC().Truncate(time.Microsecond)
	entries, _, err := clients.UpdateAndRevoke(context.Background(), target.ID,
		map[string]any{"is_active": false}, true, revokedAt)
	if err != nil {
		t.Fatalf("UpdateAndRevoke(disable) error = %v", err)
	}
	// Both of the target's live access tokens need blacklist delivery.
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want the target's two live access tokens", len(entries))
	}
	assertTokenRevokedAt(t, database, "target-a-access", "target-a-refresh", revokedAt)
	assertTokenRevokedAt(t, database, "target-b-access", "target-b-refresh", revokedAt)
	// The other client's session for the same user must survive.
	assertTokenUnrevoked(t, database, "bystander-access", "bystander-refresh")

	// The durable outbox rows are what make the Redis blacklist non-authoritative.
	var queued int64
	if err := database.Model(&model.TokenBlacklistOutbox{}).
		Where("token_id IN ?", []string{"target-a-access", "target-b-access"}).
		Count(&queued).Error; err != nil {
		t.Fatalf("count outbox rows: %v", err)
	}
	if queued != 2 {
		t.Fatalf("outbox rows = %d, want 2", queued)
	}
}

// Re-disabling an already disabled client, or updating only the name, must not
// revoke anything: revocation follows the true -> false transition, which the
// service decides, so a caller passing revokeTokens=false must be honored.
func TestOAuthClientRepositoryUpdateWithoutRevokeLeavesTokensAlone(t *testing.T) {
	database := setupDatabase(t)
	clients := repository.NewOAuthClient(database)
	tokens := repository.NewToken(database)
	users := repository.NewUser(database)
	user := createUserWithProfile(t, users, "rename-client@njupt.edu.cn")
	client := createOAuthClient(t, database)
	createTokenPair(t, tokens, "kept", "family-kept", 0, client.ID, user.ID)

	entries, _, err := clients.UpdateAndRevoke(context.Background(), client.ID,
		map[string]any{"client_name": "Renamed"}, false, time.Now())
	if err != nil {
		t.Fatalf("UpdateAndRevoke(rename) error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %d, want none for a rename", len(entries))
	}
	assertTokenUnrevoked(t, database, "kept-access", "kept-refresh")
	renamed, err := clients.FindByID(context.Background(), client.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if renamed.ClientName != "Renamed" {
		t.Fatalf("client name = %q, want Renamed", renamed.ClientName)
	}
}

// Deleting a registration is one step past disabling: the row and — through the
// ON DELETE CASCADE foreign keys — the client's authorization codes and
// access/refresh token metadata are gone, so no row is left to re-enable. The
// revocation leg must still run first, so the still-live access JTIs are
// enqueued for blacklist delivery before the cascade empties the token tables.
func TestOAuthClientRepositoryDeleteAndRevokeCascadesAndEnqueues(t *testing.T) {
	database := setupDatabase(t)
	clients := repository.NewOAuthClient(database)
	tokens := repository.NewToken(database)
	users := repository.NewUser(database)
	user := createUserWithProfile(t, users, "delete-client@njupt.edu.cn")

	target := createOAuthClient(t, database)
	other := &model.OAuthClient{
		ClientID:     "bystander-client",
		ClientName:   "Bystander",
		ClientType:   model.ClientTypeThirdParty,
		RedirectURIs: model.StringArray{"https://bystander.test/cb"},
		GrantTypes:   model.StringArray{"authorization_code"},
		Scopes:       model.StringArray{"openid"},
	}
	if err := clients.Create(context.Background(), other); err != nil {
		t.Fatalf("create bystander client: %v", err)
	}

	createTokenPair(t, tokens, "del-a", "family-del-a", 0, target.ID, user.ID)
	createTokenPair(t, tokens, "del-b", "family-del-b", 0, target.ID, user.ID)
	createTokenPair(t, tokens, "bystander", "family-bystander", 0, other.ID, user.ID)

	// An unconsumed authorization code belongs to the target and must die with it.
	redirectURI := "https://example.test/callback"
	nonce := "nonce"
	authorization := &model.OAuthAuthorization{
		Code:                "authorization-code-delete-test",
		ClientID:            target.ID,
		UserID:              user.ID,
		RedirectURI:         &redirectURI,
		Scopes:              model.StringArray{"openid"},
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Nonce:               &nonce,
		ExpiresAt:           time.Now().Add(time.Minute),
	}
	if err := database.Create(authorization).Error; err != nil {
		t.Fatalf("create authorization: %v", err)
	}

	revokedAt := time.Now().UTC().Truncate(time.Microsecond)
	entries, revokedRefresh, err := clients.DeleteAndRevoke(context.Background(), target.ID, revokedAt)
	if err != nil {
		t.Fatalf("DeleteAndRevoke error = %v", err)
	}
	// Both of the target's live access tokens need blacklist delivery, and both
	// families' unrevoked refresh tokens were revoked too.
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want the target's two live access tokens", len(entries))
	}
	if revokedRefresh != 2 {
		t.Fatalf("revokedRefresh = %d, want 2 (del-a and del-b families)", revokedRefresh)
	}

	// The registration itself is gone, so re-enabling is impossible.
	if _, findErr := clients.FindByID(context.Background(), target.ID); !errors.Is(findErr, repository.ErrNotFound) {
		t.Fatalf("FindByID(deleted) error = %v, want ErrNotFound", findErr)
	}

	// The cascade wiped every trace of the client's OAuth state.
	for table, modelValue := range map[string]any{
		"oauth_access_tokens":  &model.OAuthAccessToken{},
		"oauth_refresh_tokens": &model.OAuthRefreshToken{},
		"oauth_authorizations": &model.OAuthAuthorization{},
	} {
		var count int64
		if err := database.Model(modelValue).Where("client_id = ?", target.ID).Count(&count).Error; err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s rows for deleted client = %d, want 0 (cascade)", table, count)
		}
	}

	// The other client's session for the same user must survive.
	assertTokenUnrevoked(t, database, "bystander-access", "bystander-refresh")

	// The durable outbox rows survive the row deletion: the Redis blacklist is not
	// authoritative, so the auth-state cache must still be invalidated.
	var queued int64
	if err := database.Model(&model.TokenBlacklistOutbox{}).
		Where("token_id IN ?", []string{"del-a-access", "del-b-access"}).
		Count(&queued).Error; err != nil {
		t.Fatalf("count outbox rows: %v", err)
	}
	if queued != 2 {
		t.Fatalf("outbox rows = %d, want 2", queued)
	}

	// Deleting an id that is already gone is a no-op reported as not-found.
	if _, _, err := clients.DeleteAndRevoke(context.Background(), 999999, revokedAt); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("DeleteAndRevoke(missing) error = %v, want ErrNotFound", err)
	}
}

// A client whose access token has already expired but whose refresh token is
// still live is cut just the same — the refresh session dies — so the revocation
// count must report it. Otherwise the console would read "0 tokens revoked" for a
// deletion that killed a live session.
func TestOAuthClientRepositoryDeleteAndRevokeReportsRefreshOnlySession(t *testing.T) {
	database := setupDatabase(t)
	clients := repository.NewOAuthClient(database)
	users := repository.NewUser(database)
	user := createUserWithProfile(t, users, "refresh-only-delete@njupt.edu.cn")

	client := createOAuthClient(t, database)
	family := "refresh-only-family"
	expiredAccess := &model.OAuthAccessToken{
		TokenID:   "refresh-only-access",
		ClientID:  client.ID,
		UserID:    user.ID,
		FamilyID:  &family,
		Scopes:    model.StringArray{"openid"},
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	//nolint:gosec // G101 trips on the TokenHash field name; this is a fake refresh
	// token hash for a test fixture, not a credential.
	liveRefresh := &model.OAuthRefreshToken{
		TokenHash: "refresh-only-refresh",
		FamilyID:  family,
		Sequence:  0,
		ClientID:  client.ID,
		UserID:    user.ID,
		Scopes:    model.StringArray{"openid"},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := database.Create(expiredAccess).Error; err != nil {
		t.Fatalf("create expired access token: %v", err)
	}
	if err := database.Create(liveRefresh).Error; err != nil {
		t.Fatalf("create live refresh token: %v", err)
	}

	revokedAt := time.Now().UTC().Truncate(time.Microsecond)
	entries, revokedRefresh, err := clients.DeleteAndRevoke(context.Background(), client.ID, revokedAt)
	if err != nil {
		t.Fatalf("DeleteAndRevoke error = %v", err)
	}
	// The expired access token needs no blacklist delivery, but the live refresh
	// session was revoked and must be reported.
	if len(entries) != 0 {
		t.Fatalf("entries = %d, want 0 for an expired access token", len(entries))
	}
	if revokedRefresh != 1 {
		t.Fatalf("revokedRefresh = %d, want 1 (the live refresh session)", revokedRefresh)
	}
}
