package adminuser

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// An administrator must not be able to give up their own administrative access:
// the endpoint that would undo it is the one they just surrendered, so recovery
// needs a second administrator or direct database access.
func TestUpdateUserRefusesSelfRoleChange(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleAdmin, model.UserStateOnSAST)
	h.users.findResult.ID = testAdminID

	_, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.UserID = testAdminID
		input.Role = stringPtr(string(model.UserRoleMember))
	}))

	assertKind(t, err, KindProtected)
	if h.users.updateCalls != 0 {
		t.Fatalf("update calls = %d, want the write refused before reaching the repository", h.users.updateCalls)
	}
	assertAudited(t, h, actionUpdateUser, false, errcode.CodeForbidden)
}

// Editing your own non-role fields is allowed: the guard is about surrendering
// access, not about self-service.
func TestUpdateUserAllowsSelfNonRoleEdit(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleAdmin, model.UserStateOnSAST)
	h.users.findResult.ID = testAdminID

	result, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.UserID = testAdminID
		input.Name = stringPtr("新名字")
	}))
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if result.RevokedSessions {
		t.Fatal("RevokedSessions = true, want false when the role did not change")
	}
	if h.users.updateInput.Role != nil {
		t.Fatalf("role = %v, want it left out of an edit that did not submit one",
			h.users.updateInput.Role)
	}
}

// Submitting the role the account already holds is not a change, so the self-guard
// does not fire. Whether it revokes anything is the repository's call, made against
// the locked row; here the fake reports nothing revoked, which is what a no-op role
// write produces.
func TestUpdateUserTreatsUnchangedRoleAsNoRoleChange(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleAdmin, model.UserStateOnSAST)
	h.users.findResult.ID = testAdminID

	result, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.UserID = testAdminID
		input.Role = stringPtr(string(model.UserRoleAdmin))
	}))
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if result.RevokedSessions {
		t.Fatal("re-submitting the same role reported revoked sessions")
	}
}

// A role change must cut every session of the target in the same repository call,
// and the revoked JTIs must reach the fast-reject cache.
func TestUpdateUserRevokesSessionsOnRoleChange(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleAdmin, model.UserStateOnSAST)
	h.users.updateRevoked = true
	h.users.updateEntries = []model.BlacklistEntry{
		{TokenID: "jti-live", ExpiresAt: testNow.Add(30 * time.Minute)},
		{TokenID: "jti-expired", ExpiresAt: testNow.Add(-time.Minute)},
	}

	result, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.Role = stringPtr(string(model.UserRoleMember))
	}))
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	// The repository revoked and returned the entries; this layer must report that and
	// deliver them. Arming the guard is no longer decided here — see the repository's
	// integration tests, which assert it against the locked row.
	if !result.RevokedSessions {
		t.Fatal("a role change that revoked sessions must be reported as such")
	}
	if h.users.updateInput.Role == nil || *h.users.updateInput.Role != model.UserRoleMember {
		t.Fatalf("role passed down = %v, want member", h.users.updateInput.Role)
	}
	if !slices.Contains(h.blacklist.jtis, "jti-live") {
		t.Fatalf("blacklist jtis = %v, want the live JTI delivered", h.blacklist.jtis)
	}
	// An already-expired token is rejected by expiry alone; caching it would waste a
	// key with a negative TTL.
	if slices.Contains(h.blacklist.jtis, "jti-expired") {
		t.Fatalf("blacklist jtis = %v, want the expired JTI skipped", h.blacklist.jtis)
	}
	// The role change revoked every session; the device set must die with it, or
	// the user's device list keeps showing logins that can no longer authenticate.
	if len(h.devices.cleared) != 1 || h.devices.cleared[0] != testTargetID {
		t.Fatalf("device clears = %#v, want the target user cleared once", h.devices.cleared)
	}
}

// The gate for device cleanup is the repository's authoritative revocation
// flag, not len(entries): entries only collect still-live access tokens for
// blacklist delivery, so a demotion of a user idle for over an hour revokes
// every refresh token while returning zero entries — and the device records
// must still be cleared.
func TestUpdateUserClearsDevicesWhenRevokedWithoutEntries(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleAdmin, model.UserStateOnSAST)
	h.users.updateRevoked = true
	// No live access tokens: the repository revoked everything but returned
	// nothing to blacklist.
	h.users.updateEntries = nil

	if _, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.Role = stringPtr(string(model.UserRoleMember))
	})); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if len(h.devices.cleared) != 1 || h.devices.cleared[0] != testTargetID {
		t.Fatalf("device clears = %#v, want the target user cleared despite empty entries", h.devices.cleared)
	}
}

// An edit that revokes nothing (e.g. a pure profile-field change) must not touch
// the device set.
func TestUpdateUserWithoutRevocationLeavesDevices(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleMember, model.UserStateOnSAST)

	if _, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.Name = stringPtr("李四")
	})); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if len(h.devices.cleared) != 0 {
		t.Fatalf("device clears = %#v, want none without a session revoke", h.devices.cleared)
	}
}

// A promotion is passed straight through: whether it needs the last-admin guard is
// the repository's judgement, made against the locked row, and its integration tests
// cover both directions. This layer only has to not mangle the submitted role.
func TestUpdateUserPassesAPromotionThrough(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleMember, model.UserStateOnSAST)

	if _, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.Role = stringPtr(string(model.UserRoleAdmin))
	})); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if h.users.updateInput.Role == nil || *h.users.updateInput.Role != model.UserRoleAdmin {
		t.Fatalf("role passed down = %v, want admin", h.users.updateInput.Role)
	}
}

// The repository owns the last-admin decision because only its transaction can
// serialize the count; the service's job is to translate the refusal.
func TestUpdateUserReportsLastAdminRefusal(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleAdmin, model.UserStateOnSAST)
	h.users.updateErr = repository.ErrLastAdmin

	_, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.Role = stringPtr(string(model.UserRoleMember))
	}))

	assertKind(t, err, KindProtected)
	assertAudited(t, h, actionUpdateUser, false, errcode.CodeForbidden)
}

func TestDeleteUserReportsLastAdminRefusal(t *testing.T) {
	h := newHarness(t)
	h.users.deleteErr = repository.ErrLastAdmin

	err := h.service.DeleteUser(context.Background(), targetInput())

	assertKind(t, err, KindProtected)
	assertAudited(t, h, actionDeleteUser, false, errcode.CodeForbidden)
}

// Each repository sentinel must keep its own meaning on the way out. Swapping two
// of these arms would tell an administrator that a user who does not exist is
// "already closed", and vice versa — both plausible enough to act on.
func TestDeleteAndRestoreTranslateEachRepositorySentinel(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		from     error
		wantKind Kind
		wantCode int
	}{
		{"missing user", repository.ErrNotFound, KindNotFound, errcode.CodeUserNotFound},
		{"already closed", repository.ErrStateConflict, KindStateConflict, errcode.CodeValidationFailed},
		{"last admin", repository.ErrLastAdmin, KindProtected, errcode.CodeForbidden},
	} {
		t.Run("delete/"+testCase.name, func(t *testing.T) {
			h := newHarness(t)
			h.users.deleteErr = testCase.from

			assertMappedTo(t, h.service.DeleteUser(context.Background(), targetInput()),
				testCase.wantKind, testCase.wantCode)
		})
	}

	for _, testCase := range []struct {
		name     string
		from     error
		wantKind Kind
		wantCode int
	}{
		{"missing user", repository.ErrNotFound, KindNotFound, errcode.CodeUserNotFound},
		{"not closed", repository.ErrStateConflict, KindStateConflict, errcode.CodeValidationFailed},
	} {
		t.Run("restore/"+testCase.name, func(t *testing.T) {
			h := newHarness(t)
			h.users.restoreErr = testCase.from

			assertMappedTo(t, h.service.RestoreUser(context.Background(), targetInput()),
				testCase.wantKind, testCase.wantCode)
		})
	}
}

// An unrecognized constraint must still be a conflict rather than a 500: the write
// lost a uniqueness race, which the caller can act on, even when the service cannot
// name the field.
func TestUpdateUserMapsUnknownConstraintToConflict(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleMember, model.UserStateOnSAST)
	h.users.updateErr = &pgconn.PgError{
		Code: pgerrcode.UniqueViolation, ConstraintName: "uq_user_something_new",
	}

	_, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.Name = stringPtr("张三")
	}))

	assertMappedTo(t, err, KindConflict, errcode.CodeConflict)
}

func assertMappedTo(t *testing.T, err error, wantKind Kind, wantCode int) {
	t.Helper()
	var serviceErr *Error
	if !errors.As(err, &serviceErr) {
		t.Fatalf("error = %v, want a typed service error", err)
	}
	if serviceErr.Kind != wantKind || serviceErr.Code != wantCode {
		t.Fatalf("kind/code = %s/%d, want %s/%d",
			serviceErr.Kind, serviceErr.Code, wantKind, wantCode)
	}
}

// Closing your own account through the console locks you out of the endpoint that
// would reopen it.
func TestDeleteUserRefusesSelf(t *testing.T) {
	h := newHarness(t)

	err := h.service.DeleteUser(context.Background(), TargetUserInput{
		UserID: testAdminID, AdminUserID: testAdminID,
	})

	assertKind(t, err, KindProtected)
	if h.users.deleteCalls != 0 {
		t.Fatalf("delete calls = %d, want the write refused before the repository", h.users.deleteCalls)
	}
}

// state=is_deleted through PUT would flip the flag without revoking anything,
// leaving a closed account holding live refresh tokens. It is refused with a
// pointer at the endpoint that does it properly.
func TestUpdateUserRefusesDeletedState(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleMember, model.UserStateOnSAST)

	_, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.State = stringPtr(string(model.UserStateDeleted))
	}))

	assertKind(t, err, KindStateConflict)
	if h.users.updateCalls != 0 {
		t.Fatalf("update calls = %d, want no write", h.users.updateCalls)
	}
}

// A closed account is edited by restoring it first; saying so beats a 404 on a
// user the console can see in its own list.
func TestUpdateUserRefusesEditingDeletedAccount(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleMember, model.UserStateDeleted)

	_, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.Name = stringPtr("新名字")
	}))

	assertKind(t, err, KindStateConflict)
	if h.users.updateCalls != 0 {
		t.Fatalf("update calls = %d, want no write on a closed account", h.users.updateCalls)
	}
}

// The three non-deleted states may move between each other freely: an
// administrator correcting a mistaken retirement is a legitimate operation, and
// the PRD's arrows describe a lifecycle rather than a management constraint.
func TestUpdateUserAllowsStateCorrection(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleMember, model.UserStateRetiredSAST)

	result, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.State = stringPtr(string(model.UserStateOnSAST))
	}))
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if h.users.updatedUserID != testTargetID {
		t.Fatalf("wrote to user %d, want the target %d", h.users.updatedUserID, testTargetID)
	}
	if !slices.Equal(result.ChangedFields, []string{"state"}) {
		t.Fatalf("changed fields = %v, want exactly the submitted field", result.ChangedFields)
	}
	if h.users.updateInput.State == nil || *h.users.updateInput.State != model.UserStateOnSAST {
		t.Fatalf("state written = %v, want on_sast", h.users.updateInput.State)
	}
	// State is not what invalidates a session; only the role is, so nothing was
	// revoked and the result must not claim otherwise.
	if result.RevokedSessions {
		t.Fatal("a state correction reported revoked sessions")
	}
}

func TestUpdateUserRejectsEmptyUpdate(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleMember, model.UserStateOnSAST)

	_, err := h.service.UpdateUser(context.Background(), updateInput(nil))

	assertKind(t, err, KindInvalidInput)
	if h.users.updateCalls != 0 {
		t.Fatalf("update calls = %d, want no write", h.users.updateCalls)
	}
}

func TestUpdateUserReportsMissingTarget(t *testing.T) {
	h := newHarness(t)
	h.users.findErr = repository.ErrNotFound

	_, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.Name = stringPtr("新名字")
	}))

	assertKind(t, err, KindNotFound)
	var serviceErr *Error
	if !errors.As(err, &serviceErr) || serviceErr.Code != errcode.CodeUserNotFound {
		t.Fatalf("code = %v, want CodeUserNotFound rather than the client one", err)
	}
}

// login_email and student_id are unique across all accounts, so an edit can lose a
// race. The administrator needs to know which field to change.
func TestUpdateUserMapsUniqueViolations(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		constraint string
		wantCode   int
	}{
		{"login email", userLoginEmailConstraint, errcode.CodeEmailAlreadyRegistered},
		{"student id", userStudentIDConstraint, errcode.CodeStudentIDOccupied},
		// V005 raises this from a trigger when the address is already bound as an
		// other_mail identity, using unique_violation so it arrives here like any duplicate.
		{"login email bound as identity", userLoginEmailIsIdentityConstraint, errcode.CodeEmailAlreadyRegistered},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t)
			h.users.findResult = targetUser(model.UserRoleMember, model.UserStateOnSAST)
			h.users.updateErr = &pgconn.PgError{
				Code: pgerrcode.UniqueViolation, ConstraintName: testCase.constraint,
			}

			_, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
				input.LoginEmail = stringPtr("someone@sast.fun")
				input.EmailType = stringPtr(string(model.EmailTypeSAST))
			}))

			var serviceErr *Error
			if !errors.As(err, &serviceErr) {
				t.Fatalf("error = %v, want a typed service error", err)
			}
			if serviceErr.Kind != KindConflict || serviceErr.Code != testCase.wantCode {
				t.Fatalf("kind/code = %s/%d, want conflict/%d",
					serviceErr.Kind, serviceErr.Code, testCase.wantCode)
			}
		})
	}
}

// The audit trail must record the field names that changed and never their values:
// a login_email or student_id written into detail outlives the request and is
// readable by every administrator.
func TestUpdateUserAuditRecordsFieldNamesNotValues(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleMember, model.UserStateOnSAST)

	if _, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.Name = stringPtr("新名字")
		input.StudentID = stringPtr("B24040199")
	})); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	entry := assertAudited(t, h, actionUpdateUser, true, 0)
	detail := string(entry.Detail)
	for _, want := range []string{"name", "student_id"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("audit detail = %s, want it to name %q", detail, want)
		}
	}
	for _, leaked := range []string{"新名字", "B24040199"} {
		if strings.Contains(detail, leaked) {
			t.Fatalf("audit detail = %s, want it to omit the submitted value %q", detail, leaked)
		}
	}
	if entry.ResourceID == nil || *entry.ResourceID != "42" {
		t.Fatalf("resource id = %v, want the target user id", entry.ResourceID)
	}
	if entry.UserID == nil || *entry.UserID != testAdminID {
		t.Fatalf("audit user id = %v, want the acting administrator", entry.UserID)
	}
}

// The audit trail must say which credential acted, not just which administrator. A
// delegated client's token and a console session name the same person, so without
// actor_client_id the two are indistinguishable after the fact.
func TestAuditRecordsTheActingClient(t *testing.T) {
	const delegated = "ops-tool-delegate"
	tests := []struct {
		name  string
		actor string
		want  string
	}{
		{name: "delegated client", actor: delegated, want: delegated},
		// An empty azp is a console session: recorded as the built-in client explicitly,
		// so NULL keeps meaning "no OAuth credential authorized this".
		{name: "console session", actor: "", want: testConsoleClientID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Both write paths: one carries a Detail map, the other does not.
			t.Run("update", func(t *testing.T) {
				h := newHarness(t)
				h.users.findResult = targetUser(model.UserRoleMember, model.UserStateOnSAST)
				name := "新名字"
				_, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
					input.Name = &name
					input.ActorClientID = test.actor
				}))
				if err != nil {
					t.Fatalf("UpdateUser() error = %v", err)
				}
				assertActor(t, h, test.want)
			})
			t.Run("delete", func(t *testing.T) {
				h := newHarness(t)
				h.users.findResult = targetUser(model.UserRoleMember, model.UserStateOnSAST)
				input := targetInput()
				input.ActorClientID = test.actor
				if err := h.service.DeleteUser(context.Background(), input); err != nil {
					t.Fatalf("DeleteUser() error = %v", err)
				}
				assertActor(t, h, test.want)
			})
		})
	}
}

// With no console client configured the column stays NULL rather than being filled
// with a guess: an audit row naming a client that never acted is worse than one
// admitting it does not know.
func TestAuditOmitsActorWhenConsoleClientIsUnset(t *testing.T) {
	h := newHarness(t)
	h.service.ConsoleClientID = ""
	h.users.findResult = targetUser(model.UserRoleMember, model.UserStateOnSAST)

	if err := h.service.DeleteUser(context.Background(), targetInput()); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	if got := h.audit.entries[0].ActorClientID; got != nil {
		t.Fatalf("actor client id = %q, want nil", *got)
	}
}

func assertActor(t *testing.T, h *harness, want string) {
	t.Helper()
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	actor := h.audit.entries[0].ActorClientID
	if actor == nil || *actor != want {
		t.Fatalf("actor client id = %v, want %q", actor, want)
	}
}

func TestRestoreUserReportsLiveAccount(t *testing.T) {
	h := newHarness(t)
	h.users.restoreErr = repository.ErrStateConflict

	err := h.service.RestoreUser(context.Background(), targetInput())

	assertKind(t, err, KindStateConflict)
	assertAudited(t, h, actionRestoreUser, false, errcode.CodeValidationFailed)
}

func TestRestoreUserSucceeds(t *testing.T) {
	h := newHarness(t)

	if err := h.service.RestoreUser(context.Background(), targetInput()); err != nil {
		t.Fatalf("RestoreUser: %v", err)
	}
	if h.users.restoredUserID != testTargetID {
		t.Fatalf("restored user = %d, want %d", h.users.restoredUserID, testTargetID)
	}
	assertAudited(t, h, actionRestoreUser, true, 0)
}

func TestDeleteUserDeliversRevokedTokens(t *testing.T) {
	h := newHarness(t)
	h.users.deleteEntries = []model.BlacklistEntry{
		{TokenID: "jti-a", ExpiresAt: testNow.Add(time.Hour)},
	}

	if err := h.service.DeleteUser(context.Background(), targetInput()); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if h.users.deletedUserID != testTargetID {
		t.Fatalf("closed user %d, want the target %d", h.users.deletedUserID, testTargetID)
	}
	if !slices.Contains(h.blacklist.jtis, "jti-a") {
		t.Fatalf("blacklist jtis = %v, want the revoked JTI delivered", h.blacklist.jtis)
	}
	// Closing the account cut every session; the device records must not outlive
	// the account as ghost logins.
	if len(h.devices.cleared) != 1 || h.devices.cleared[0] != testTargetID {
		t.Fatalf("device clears = %#v, want the closed user's records cleared", h.devices.cleared)
	}
	assertAudited(t, h, actionDeleteUser, true, 0)
}

// A blacklist failure must not fail the request: the outbox row was written in the
// revoking transaction and the auth middleware checks the database anyway.
func TestDeleteUserSurvivesBlacklistFailure(t *testing.T) {
	h := newHarness(t)
	h.users.deleteEntries = []model.BlacklistEntry{
		{TokenID: "jti-a", ExpiresAt: testNow.Add(time.Hour)},
	}
	h.blacklist.err = errors.New("redis unavailable")

	if err := h.service.DeleteUser(context.Background(), targetInput()); err != nil {
		t.Fatalf("DeleteUser: %v, want the revocation to stand despite the cache", err)
	}
}

// A failed audit write must not fail an action that already committed.
func TestDeleteUserSurvivesAuditFailure(t *testing.T) {
	h := newHarness(t)
	h.audit.createErr = errors.New("audit table unavailable")

	if err := h.service.DeleteUser(context.Background(), targetInput()); err != nil {
		t.Fatalf("DeleteUser: %v, want the delete to stand despite the audit", err)
	}
}

// The audit write must outlive a cancelled request: an action that already
// committed is exactly what the trail must not lose.
func TestAuditIsWrittenAfterCallerCancels(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := h.service.RestoreUser(ctx, targetInput()); err != nil {
		t.Fatalf("RestoreUser: %v", err)
	}
	assertAudited(t, h, actionRestoreUser, true, 0)
}

func TestGetUserOmitsPasswordHash(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleMember, model.UserStateOnSAST)

	detail, err := h.service.GetUser(context.Background(), testTargetID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if detail.ID != testTargetID || detail.LoginEmail != "b24040101@njupt.edu.cn" {
		t.Fatalf("detail = %+v, want the target account", detail)
	}
	// A user with neither a profile row nor a binding maps to a nil profile and an
	// empty slice, so the JSON carries [] rather than null.
	if detail.Profile != nil {
		t.Fatalf("profile = %+v, want nil for a user with no profile row", detail.Profile)
	}
	if identities := detail.Identities; identities == nil {
		t.Fatal("identities = nil, want an empty slice so the JSON is not null")
	}
}

// Assembling the profile and the bindings is the whole job of GET /admin/users/:id.
// Without this the mapper could return a null profile and an empty binding list for
// a user who has both, and every other test would still pass: they all use a target
// with neither.
func TestGetUserMapsProfileAndIdentities(t *testing.T) {
	h := newHarness(t)
	user := targetUser(model.UserRoleMember, model.UserStateOnSAST)
	nickname := "三儿"
	department := model.DepartmentSoftware
	avatar := "https://cdn.test/a.png"
	expiresAt := testNow.Add(time.Hour)
	user.Profile = &model.Profile{
		UserID:     user.ID,
		Nickname:   &nickname,
		Department: &department,
		Avatar:     &avatar,
		CreatedAt:  testNow,
		UpdatedAt:  testNow,
	}
	user.Identities = []model.Identity{
		{
			ID: 11, UserID: user.ID, Provider: model.LoginMethodGitHub,
			ProviderID: "gh-123", IdentityData: model.JSONB(`{"mobile":"+8613000288399"}`),
			// Provider credentials are stored on the row but must not survive the mapping.
			AccessToken: stringPtr("gho_secret"), RefreshToken: stringPtr("ghr_secret"),
			TokenExpiresAt: &expiresAt, CreatedAt: testNow, UpdatedAt: testNow,
		},
		{
			ID: 12, UserID: user.ID, Provider: model.LoginMethodOtherMail,
			ProviderID: "alt@njupt.edu.cn", CreatedAt: testNow, UpdatedAt: testNow,
		},
	}
	h.users.findResult = user

	detail, err := h.service.GetUser(context.Background(), testTargetID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if detail.Profile == nil {
		t.Fatal("profile = nil, want the user's profile row mapped")
	}
	if detail.Profile.Nickname == nil || *detail.Profile.Nickname != nickname {
		t.Fatalf("nickname = %v, want %q", detail.Profile.Nickname, nickname)
	}
	if detail.Profile.Department == nil || *detail.Profile.Department != string(department) {
		t.Fatalf("department = %v, want software", detail.Profile.Department)
	}
	if len(detail.Identities) != 2 {
		t.Fatalf("identities = %d, want both bindings", len(detail.Identities))
	}
	first := detail.Identities[0]
	if first.ID != 11 || first.Provider != string(model.LoginMethodGitHub) || first.ProviderID != "gh-123" {
		t.Fatalf("first identity = %+v, want the GitHub binding", first)
	}
	if first.TokenExpiresAt == nil || !first.TokenExpiresAt.Equal(expiresAt) {
		t.Fatalf("token_expires_at = %v, want %v", first.TokenExpiresAt, expiresAt)
	}
	// The console lists bindings; it does not hand out the provider credentials behind
	// them. UserIdentity has no field for them, so this pins the type's shape.
	rendered, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}
	// identity_data is the provider's whole user object — the documented Lark payload
	// carries mobile, email, enterprise_email and employee_no — and these endpoints are
	// readable by lecturers, not only administrators. Listing a binding must not hand
	// over the contact details behind it.
	for _, leaked := range []string{
		"gho_secret", "ghr_secret", user.PasswordHash, "+8613000288399", "mobile",
	} {
		if strings.Contains(string(rendered), leaked) {
			t.Fatalf("detail leaked %q: %s", leaked, rendered)
		}
	}
}

func TestGetUserRejectsNonPositiveID(t *testing.T) {
	h := newHarness(t)

	_, err := h.service.GetUser(context.Background(), 0)

	assertKind(t, err, KindNotFound)
}

func assertKind(t *testing.T, err error, want Kind) {
	t.Helper()
	var serviceErr *Error
	if !errors.As(err, &serviceErr) {
		t.Fatalf("error = %v, want a typed service error", err)
	}
	if serviceErr.Kind != want {
		t.Fatalf("kind = %s, want %s", serviceErr.Kind, want)
	}
}

// assertAudited checks that exactly one entry was recorded with the expected
// action, outcome and business code. Failure paths are audited too: an admin
// probing for accounts must leave a trail.
func assertAudited(t *testing.T, h *harness, action string, success bool, errCode int) *model.AuditLog {
	t.Helper()
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want exactly 1", len(h.audit.entries))
	}
	entry := h.audit.entries[0]
	if entry.Action != action {
		t.Fatalf("action = %q, want %q", entry.Action, action)
	}
	if entry.Resource != auditResourceUser {
		t.Fatalf("resource = %q, want %q", entry.Resource, auditResourceUser)
	}
	if entry.Success == nil || *entry.Success != success {
		t.Fatalf("success = %v, want %v", entry.Success, success)
	}
	// The caller's address and agent are what make a row attributable to a person
	// rather than just to an account, so every audited path must carry them through.
	if entry.ClientIP == nil || *entry.ClientIP != testClientIP {
		t.Fatalf("client ip = %v, want %q", entry.ClientIP, testClientIP)
	}
	if entry.UserAgent == nil || *entry.UserAgent != testUserAgent {
		t.Fatalf("user agent = %v, want %q", entry.UserAgent, testUserAgent)
	}
	if errCode == 0 {
		if entry.ErrCode != nil {
			t.Fatalf("err code = %v, want none on success", entry.ErrCode)
		}
		return entry
	}
	if entry.ErrCode == nil || *entry.ErrCode != errCode {
		t.Fatalf("err code = %v, want %d", entry.ErrCode, errCode)
	}
	return entry
}

// state_auto is the undo for a manual pin. It must reach the repository as a
// derivation request, must not be accepted alongside an explicit state (two
// instructions for one column), and must count as a change on its own — a
// request that only re-derives is still a request that writes.
func TestUpdateUserStateAuto(t *testing.T) {
	t.Run("reaches the repository and counts as a change", func(t *testing.T) {
		h := newHarness(t)
		h.users.findResult = targetUser(model.UserRoleMember, model.UserStateOnSAST)
		stateAuto := true
		result, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
			input.StateAuto = &stateAuto
		}))
		if err != nil {
			t.Fatalf("UpdateUser(state_auto): %v", err)
		}
		if !h.users.updateInput.StateAuto {
			t.Fatal("StateAuto did not reach the repository")
		}
		if h.users.updateInput.State != nil {
			t.Fatalf("State = %v, want nil: the value is derived inside the transaction", *h.users.updateInput.State)
		}
		if !slices.Contains(result.ChangedFields, "state_auto") {
			t.Fatalf("changed fields = %v, want state_auto recorded for the audit trail", result.ChangedFields)
		}
	})

	t.Run("is refused alongside an explicit state", func(t *testing.T) {
		h := newHarness(t)
		stateAuto := true
		state := "on_sast"
		_, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
			input.StateAuto = &stateAuto
			input.State = &state
		}))
		assertKind(t, err, KindInvalidInput)
		if h.users.updateCalls != 0 {
			t.Fatalf("update calls = %d, want no write", h.users.updateCalls)
		}
	})

	t.Run("false alone is not a change", func(t *testing.T) {
		h := newHarness(t)
		stateAuto := false
		_, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
			input.StateAuto = &stateAuto
		}))
		assertKind(t, err, KindInvalidInput)
		if h.users.updateCalls != 0 {
			t.Fatalf("update calls = %d, want no write", h.users.updateCalls)
		}
	})
}

// state written by hand is a decision, so the repository is told to pin it; a
// derived default is not sent at all.
func TestUpdateUserStatePassesPinToRepository(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleMember, model.UserStateNJUPTer)
	state := "on_sast"
	if _, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.State = &state
	})); err != nil {
		t.Fatalf("UpdateUser(state): %v", err)
	}
	if h.users.updateInput.StateAuto {
		t.Fatal("StateAuto set alongside an explicit state")
	}
	if h.users.updateInput.State == nil || *h.users.updateInput.State != model.UserStateOnSAST {
		t.Fatalf("State = %v, want on_sast passed down", h.users.updateInput.State)
	}
}
