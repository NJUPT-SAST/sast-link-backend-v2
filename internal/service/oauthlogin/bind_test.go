package oauthlogin

import (
	"context"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/provider"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func TestBindCreatesIdentityForAuthenticatedCaller(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)

	result, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if result.Identity.UserID != 42 {
		t.Fatalf("bound to user %d, want 42", result.Identity.UserID)
	}
	if result.Identity.ProviderID != "145339646" {
		t.Fatalf("provider_id = %q, want 145339646", result.Identity.ProviderID)
	}
	if result.Identity.AccessToken == nil || *result.Identity.AccessToken != "gho_token" {
		t.Fatal("provider access token was not persisted on the binding")
	}
	// identity_data is raw JSON, so assert it decoded rather than comparing maps.
	if len(result.Identity.IdentityData) == 0 {
		t.Fatal("identity_data was not stored")
	}

	actions := doubles.Audits.actions()
	if len(actions) == 0 || actions[0] != "oauth_bind" {
		t.Fatalf("audit actions = %v, want oauth_bind", actions)
	}
}

func TestBindRejectsAccountOwnedByAnotherUser(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	// Someone else already owns this GitHub account.
	doubles.Identities.put(&model.Identity{
		UserID: 7, Provider: model.LoginMethodGitHub, ProviderID: "145339646",
	})

	_, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "secret",
	})
	assertKind(t, err, KindConflict, errcode.CodeIdentityOccupied)
}

func TestBindRejectsSecondBindingOfSameProvider(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	// The caller already holds a GitHub binding, but to a different account, so
	// the pre-check misses and the per-user cap is what rejects it.
	doubles.Identities.put(&model.Identity{
		UserID: 42, Provider: model.LoginMethodGitHub, ProviderID: "999",
	})

	_, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "secret",
	})
	// 40904, not 40903: the caller owns the existing binding.
	assertKind(t, err, KindConflict, errcode.CodeIdentityAlreadyBound)
}

func TestBindReportsAlreadyBoundWhenSameAccountRepeats(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	doubles.Identities.put(&model.Identity{
		UserID: 42, Provider: model.LoginMethodGitHub, ProviderID: "145339646",
	})

	_, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "secret",
	})
	assertKind(t, err, KindConflict, errcode.CodeIdentityAlreadyBound)
	// Repeating the bind still refreshes the stored credentials, so a user whose
	// provider token expired is not stuck with a stale one.
	if _, ok := doubles.Identities.updated[1]; !ok {
		t.Fatal("credentials were not refreshed on a repeated bind")
	}
}

func TestBindMapsUniqueViolationRaceToOccupied(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	// Simulate losing the race: the pre-check saw no owner, but the insert hits
	// the global (provider, provider_id) unique index.
	doubles.Identities.createErr = &pgUniqueViolation{constraint: identityProviderConstraint}

	_, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "secret",
	})
	assertKind(t, err, KindConflict, errcode.CodeIdentityOccupied)
}

func TestBindMapsPerUserIndexRaceToAlreadyBound(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	doubles.Identities.createErr = &pgUniqueViolation{constraint: identityUserGitHubConstraint}

	_, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "secret",
	})
	assertKind(t, err, KindConflict, errcode.CodeIdentityAlreadyBound)
}

func TestBindMapsLimitExceededToAlreadyBound(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	doubles.Identities.createErr = repository.ErrLimitExceeded

	_, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "secret",
	})
	assertKind(t, err, KindConflict, errcode.CodeIdentityAlreadyBound)
}

func TestBindRefusesDeletedAccount(t *testing.T) {
	service, doubles := newTestService(t)
	deleted := activeUser(42)
	deleted.State = model.UserStateDeleted
	doubles.Users.byID[42] = deleted

	_, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "secret",
	})
	assertKind(t, err, KindUserDeleted, errcode.CodeAccountDeleted)
	// The provider must not even be contacted for a closed account.
	if doubles.GitHub.calls != 0 {
		t.Fatal("a deleted account reached the provider exchange")
	}
}

func TestBindRejectsMissingPrincipal(t *testing.T) {
	service, _ := newTestService(t)
	_, err := service.Bind(context.Background(), BindInput{
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "secret",
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

func TestBindRejectsMissingCode(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)

	_, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

func TestBindPropagatesForeignTenant(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	doubles.GitHub.err = provider.ErrForeignTenant

	_, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "secret",
	})
	assertKind(t, err, KindForbidden, errcode.CodeLarkTenantRequired)
}

func TestBindDoesNotConsumeAnyOAuthState(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	// Seed a live state to prove the bind path leaves it alone: binding is
	// authenticated by the Bearer token, and must never accept or consume a
	// registration_state or oauth_state as a credential.
	if err := doubles.States.SaveOAuthState(context.Background(), "os_untouched",
		StatePayload{Provider: model.LoginMethodGitHub}, 0); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	if err := doubles.Registration.SaveRegistrationState(context.Background(), "rs_untouched",
		RegistrationPayload{Provider: model.LoginMethodGitHub, ProviderID: "145339646"}, 0); err != nil {
		t.Fatalf("seed registration state: %v", err)
	}

	if _, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "secret",
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if _, ok := doubles.States.states["os_untouched"]; !ok {
		t.Fatal("Bind consumed an OAuth state")
	}
	if _, ok := doubles.Registration.states["rs_untouched"]; !ok {
		t.Fatal("Bind consumed a registration state")
	}
}
