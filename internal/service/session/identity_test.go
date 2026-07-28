package session

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

func TestListIdentitiesReturnsOwnedBindings(t *testing.T) {
	service := newRegisterService(t)
	identities := service.Identities.(*fakeIdentities)
	identities.byProviderID = map[string]*model.Identity{
		"mine@gmail.com":  {ID: 2, UserID: 42, Provider: model.LoginMethodOtherMail, ProviderID: "mine@gmail.com"},
		"other@gmail.com": {ID: 3, UserID: 99, Provider: model.LoginMethodOtherMail, ProviderID: "other@gmail.com"},
		"145339646":       {ID: 1, UserID: 42, Provider: model.LoginMethodGitHub, ProviderID: "145339646"},
	}
	result, err := service.ListIdentities(context.Background(), ListIdentitiesInput{UserID: 42})
	if err != nil {
		t.Fatalf("ListIdentities returned error: %v", err)
	}
	if len(result.Identities) != 2 {
		t.Fatalf("identities = %d, want only the caller's 2", len(result.Identities))
	}
	if result.Identities[0].ID != 1 || result.Identities[1].ID != 2 {
		t.Fatalf("identities = %+v, want ascending IDs", result.Identities)
	}
}

func TestListIdentitiesReturnsEmptySliceNotNil(t *testing.T) {
	service := newRegisterService(t)
	result, err := service.ListIdentities(context.Background(), ListIdentitiesInput{UserID: 42})
	if err != nil {
		t.Fatalf("ListIdentities returned error: %v", err)
	}
	if result.Identities == nil {
		t.Fatal("identities = nil, want empty slice so the JSON renders []")
	}
}

// bindableService gives user 42 a second other_mail identity to unbind, on top of
// the github binding testUserWithHash already assigns.
func bindableService(t *testing.T) Service {
	t.Helper()
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	identity := model.Identity{
		ID: 12, UserID: 42, Provider: model.LoginMethodOtherMail, ProviderID: "extra@gmail.com",
	}
	users.byID[42].Identities = append(users.byID[42].Identities, identity)
	service.Identities.(*fakeIdentities).byProviderID = map[string]*model.Identity{
		"extra@gmail.com": &identity,
	}
	return service
}

func TestUnbindIdentityDeletesOwnedBinding(t *testing.T) {
	service := bindableService(t)
	result, err := service.UnbindIdentity(context.Background(), UnbindIdentityInput{
		UserID: 42, IdentityID: 12, Password: "secret",
	})
	if err != nil {
		t.Fatalf("UnbindIdentity returned error: %v", err)
	}
	if result.Provider != string(model.LoginMethodOtherMail) || result.ProviderID != "extra@gmail.com" {
		t.Fatalf("result = %+v, want the unbound other_mail identity", result)
	}
	identities := service.Identities.(*fakeIdentities)
	if !slices.Equal(identities.deleted, []int64{12}) {
		t.Fatalf("deleted = %v, want [12]", identities.deleted)
	}
	audit := service.Audit.(*fakeAudit)
	entry := audit.entries[len(audit.entries)-1]
	if entry.Action != "oauth_unbind" || entry.Resource != "identity" {
		t.Fatalf("audit entry = %+v, want oauth_unbind on identity", entry)
	}
}

// A stolen access token alone must not be enough to strip login methods off an
// account, so the wrong password stops the delete.
func TestUnbindIdentityRequiresCorrectPassword(t *testing.T) {
	service := bindableService(t)
	_, err := service.UnbindIdentity(context.Background(), UnbindIdentityInput{
		UserID: 42, IdentityID: 12, Password: "wrong-password",
	})
	assertKind(t, err, KindPasswordInvalid, errcode.CodePasswordInvalid)
	if deleted := service.Identities.(*fakeIdentities).deleted; len(deleted) != 0 {
		t.Fatalf("deleted = %v, want nothing deleted on wrong password", deleted)
	}
	if code := lastErrCode(service.Audit.(*fakeAudit)); code != errcode.CodePasswordInvalid {
		t.Fatalf("audit err_code = %d, want %d", code, errcode.CodePasswordInvalid)
	}
}

// Another user's binding ID and a nonexistent one must be indistinguishable, or
// an authenticated caller can enumerate which identity IDs exist.
func TestUnbindIdentityHidesForeignBindings(t *testing.T) {
	service := bindableService(t)
	identities := service.Identities.(*fakeIdentities)
	identities.byProviderID["foreign@gmail.com"] = &model.Identity{
		ID: 77, UserID: 99, Provider: model.LoginMethodOtherMail, ProviderID: "foreign@gmail.com",
	}
	_, foreign := service.UnbindIdentity(context.Background(), UnbindIdentityInput{
		UserID: 42, IdentityID: 77, Password: "secret",
	})
	_, missing := service.UnbindIdentity(context.Background(), UnbindIdentityInput{
		UserID: 42, IdentityID: 4242, Password: "secret",
	})
	for name, err := range map[string]error{"foreign": foreign, "missing": missing} {
		t.Run(name, func(t *testing.T) {
			assertKind(t, err, KindNotFound, errcode.CodeNotFound)
		})
	}
	if identities.byProviderID["foreign@gmail.com"] == nil {
		t.Fatal("foreign identity was deleted")
	}
}

// Unbinding the only remaining login method would lock the owner out of their own
// account, so it is rejected even with the correct password.
func TestUnbindIdentityRejectsLastLoginMethod(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	user := users.byID[42]
	// No login email and a single identity: that identity is the only way in.
	user.LoginEmail = ""
	only := model.Identity{ID: 12, UserID: 42, Provider: model.LoginMethodOtherMail, ProviderID: "only@gmail.com"}
	user.Identities = []model.Identity{only}
	service.Identities.(*fakeIdentities).byProviderID = map[string]*model.Identity{"only@gmail.com": &only}

	_, err := service.UnbindIdentity(context.Background(), UnbindIdentityInput{
		UserID: 42, IdentityID: 12, Password: "secret",
	})
	assertKind(t, err, KindValidationFailed, errcode.CodeValidationFailed)
	if deleted := service.Identities.(*fakeIdentities).deleted; len(deleted) != 0 {
		t.Fatalf("deleted = %v, want the last login method kept", deleted)
	}
}

// A user who still holds a login email always keeps a way in, so unbinding their
// only identity is allowed.
func TestUnbindIdentityAllowsLastIdentityWhenLoginEmailRemains(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	only := model.Identity{ID: 12, UserID: 42, Provider: model.LoginMethodOtherMail, ProviderID: "only@gmail.com"}
	users.byID[42].Identities = []model.Identity{only}
	service.Identities.(*fakeIdentities).byProviderID = map[string]*model.Identity{"only@gmail.com": &only}

	if _, err := service.UnbindIdentity(context.Background(), UnbindIdentityInput{
		UserID: 42, IdentityID: 12, Password: "secret",
	}); err != nil {
		t.Fatalf("UnbindIdentity returned error: %v", err)
	}
}

// The cooldown is claimed before the delete, so a second immediate attempt is
// rejected rather than both passing the check.
func TestUnbindIdentityEnforcesCooldown(t *testing.T) {
	service := bindableService(t)
	cooldowns := service.UnbindCooldowns.(*fakeUnbindCooldowns)
	cooldowns.held = map[string]bool{"extra@gmail.com": true}
	cooldowns.retryAfter = 42

	_, err := service.UnbindIdentity(context.Background(), UnbindIdentityInput{
		UserID: 42, IdentityID: 12, Password: "secret",
	})
	assertKind(t, err, KindRateLimited, errcode.CodeRateLimited)
	if deleted := service.Identities.(*fakeIdentities).deleted; len(deleted) != 0 {
		t.Fatalf("deleted = %v, want nothing deleted while cooling down", deleted)
	}
}

// A delete that fails must release the claim: holding it would block a legitimate
// retry for the full window over an error the user did not cause.
func TestUnbindIdentityReleasesCooldownOnDeleteFailure(t *testing.T) {
	service := bindableService(t)
	service.Identities.(*fakeIdentities).deleteErr = errors.New("boom")

	_, err := service.UnbindIdentity(context.Background(), UnbindIdentityInput{
		UserID: 42, IdentityID: 12, Password: "secret",
	})
	assertKind(t, err, KindInternal, errcode.CodeInternal)
	cooldowns := service.UnbindCooldowns.(*fakeUnbindCooldowns)
	if !slices.Equal(cooldowns.releases, []string{"extra@gmail.com"}) {
		t.Fatalf("releases = %v, want the claim released", cooldowns.releases)
	}
}

// A cancelled caller is the most likely reason the delete failed, and it is the
// case where holding the claim hurts most: nothing was unbound, yet the address
// would stay locked for the rest of the window. The release must therefore not
// ride on the caller's context.
func TestUnbindIdentityReleasesCooldownWhenCallerCancelled(t *testing.T) {
	service := bindableService(t)
	service.Identities.(*fakeIdentities).deleteErr = context.Canceled

	ctx, cancel := context.WithCancel(context.Background())
	primed := make(chan struct{})
	service.Identities.(*fakeIdentities).beforeDelete = func() {
		close(primed)
		cancel()
	}

	_, err := service.UnbindIdentity(ctx, UnbindIdentityInput{
		UserID: 42, IdentityID: 12, Password: "secret",
	})
	if err == nil {
		t.Fatal("UnbindIdentity() error = nil, want failure")
	}
	<-primed
	cooldowns := service.UnbindCooldowns.(*fakeUnbindCooldowns)
	if !slices.Equal(cooldowns.releases, []string{"extra@gmail.com"}) {
		t.Fatalf("releases = %v, want the claim released despite cancellation", cooldowns.releases)
	}
	if cooldowns.held["extra@gmail.com"] {
		t.Fatal("claim still held after a cancelled unbind failed")
	}
}

// The cooldown is fail-open per PRD §6.0: PostgreSQL owns the binding state, so a
// Redis outage must not block a password-confirmed unbind.
func TestUnbindIdentityFailsOpenWhenCooldownUnavailable(t *testing.T) {
	service := bindableService(t)
	service.UnbindCooldowns.(*fakeUnbindCooldowns).err = errors.New("redis down")

	if _, err := service.UnbindIdentity(context.Background(), UnbindIdentityInput{
		UserID: 42, IdentityID: 12, Password: "secret",
	}); err != nil {
		t.Fatalf("UnbindIdentity returned error: %v, want fail-open", err)
	}
	if deleted := service.Identities.(*fakeIdentities).deleted; !slices.Equal(deleted, []int64{12}) {
		t.Fatalf("deleted = %v, want [12]", deleted)
	}
}

func TestUnbindIdentityRejectsEmptyPassword(t *testing.T) {
	service := bindableService(t)
	_, err := service.UnbindIdentity(context.Background(), UnbindIdentityInput{
		UserID: 42, IdentityID: 12,
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

func TestUnbindIdentityRejectsDeletedUser(t *testing.T) {
	service := bindableService(t)
	service.Users.(*fakeUsers).byID[42].State = model.UserStateDeleted

	_, err := service.UnbindIdentity(context.Background(), UnbindIdentityInput{
		UserID: 42, IdentityID: 12, Password: "secret",
	})
	assertKind(t, err, KindUserDeleted, errcode.CodeAccountDeleted)
}
