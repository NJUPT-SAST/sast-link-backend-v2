package session

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

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

// Throttled before the password check, so guessing attempts consume the budget
// too. The old cooldown was claimed only after the password verified, which left
// this endpoint with no protection against guessing at all — and it has no
// login-failure counter of its own.
func TestUnbindIdentityThrottlesBeforePasswordCheck(t *testing.T) {
	service := bindableService(t)
	service.UnbindLimiter = &fakeLimiter{result: LimitResult{Allowed: false, RetryAfter: 42 * time.Second}}
	audits := service.Audit.(*fakeAudit)
	before := len(audits.entries)

	_, err := service.UnbindIdentity(context.Background(), UnbindIdentityInput{
		UserID: 42, IdentityID: 12, Password: "wrong-password",
	})
	assertKind(t, err, KindRateLimited, errcode.CodeRateLimited)
	// A rejected password writes an audit entry; a throttled request never reaches
	// the check, so nothing is recorded.
	if len(audits.entries) != before {
		t.Fatalf("audit entries grew by %d, want 0 — the limiter must run first", len(audits.entries)-before)
	}
	if deleted := service.Identities.(*fakeIdentities).deleted; len(deleted) != 0 {
		t.Fatalf("deleted = %v, want nothing deleted while throttled", deleted)
	}
}

// Keyed per caller, not per address. Keying by provider_id let one user's unbind
// lock out a different user who later bound the same address.
func TestUnbindIdentityThrottlesPerUser(t *testing.T) {
	service := bindableService(t)
	limiter := &fakeLimiter{}
	service.UnbindLimiter = limiter

	if _, err := service.UnbindIdentity(context.Background(), UnbindIdentityInput{
		UserID: 42, IdentityID: 12, Password: "secret",
	}); err != nil {
		t.Fatalf("UnbindIdentity returned error: %v", err)
	}
	if want := []string{"unbind:user:42"}; !slices.Equal(limiter.calls, want) {
		t.Fatalf("limiter calls = %v, want %v", limiter.calls, want)
	}
}

// Fail-open per PRD §6.0: PostgreSQL owns the binding state, so a limiter outage
// must not block a password-confirmed unbind.
func TestUnbindIdentityFailsOpenWhenLimiterUnavailable(t *testing.T) {
	service := bindableService(t)
	service.UnbindLimiter = &fakeLimiter{err: errors.New("redis down")}

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
