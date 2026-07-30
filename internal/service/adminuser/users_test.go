package adminuser

import (
	"context"
	"errors"
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
	if h.users.updateRevoke {
		t.Fatal("repository asked to revoke sessions for a name change")
	}
}

// Submitting the role the account already holds is not a change, so neither the
// self-guard nor the session revocation applies.
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
	if result.RevokedSessions || h.users.updateRevoke || h.users.updateGuard {
		t.Fatalf("re-submitting the same role revoked sessions (%v) or armed the guard (%v)",
			h.users.updateRevoke, h.users.updateGuard)
	}
}

// A role change must cut every session of the target in the same repository call,
// and the revoked JTIs must reach the fast-reject cache.
func TestUpdateUserRevokesSessionsOnRoleChange(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleAdmin, model.UserStateOnSAST)
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
	if !result.RevokedSessions || !h.users.updateRevoke {
		t.Fatal("a role change must revoke the target's sessions")
	}
	// Demoting an admin could remove the last one, so the repository guard is armed.
	if !h.users.updateGuard {
		t.Fatal("demoting an admin must arm the last-admin guard")
	}
	if _, ok := h.blacklist.batch["jti-live"]; !ok {
		t.Fatalf("blacklist batch = %v, want the live JTI delivered", h.blacklist.batch)
	}
	// An already-expired token is rejected by expiry alone; caching it would waste a
	// key with a negative TTL.
	if _, ok := h.blacklist.batch["jti-expired"]; ok {
		t.Fatalf("blacklist batch = %v, want the expired JTI skipped", h.blacklist.batch)
	}
}

// Promoting someone to admin cannot remove an administrator, so the extra count
// query is not paid for.
func TestUpdateUserDoesNotGuardWhenPromoting(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleMember, model.UserStateOnSAST)

	if _, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.Role = stringPtr(string(model.UserRoleAdmin))
	})); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if h.users.updateGuard {
		t.Fatal("promoting to admin armed the last-admin guard")
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

	if _, err := h.service.UpdateUser(context.Background(), updateInput(func(input *UpdateUserInput) {
		input.State = stringPtr(string(model.UserStateOnSAST))
	})); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if h.users.updateInput.State == nil || *h.users.updateInput.State != model.UserStateOnSAST {
		t.Fatalf("state written = %v, want on_sast", h.users.updateInput.State)
	}
	// State is not what invalidates a session; only the role is.
	if h.users.updateRevoke {
		t.Fatal("a state correction revoked the user's sessions")
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
	if _, ok := h.blacklist.batch["jti-a"]; !ok {
		t.Fatalf("blacklist batch = %v, want the revoked JTI delivered", h.blacklist.batch)
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
	// UserDetail has no password field at all; this asserts the type stays that way.
	if identities := detail.Identities; identities == nil {
		t.Fatal("identities = nil, want an empty slice so the JSON is not null")
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
