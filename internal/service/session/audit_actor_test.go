package session

import (
	"context"
	"testing"
	"time"
)

// The /user self-service surface was opened to user:* third-party tokens in
// PR#47; those tokens' actions must land in audit_logs with a real
// actor_client_id (the azp), and a console session must name the built-in
// client rather than NULL — otherwise NULL, the contract's "no OAuth
// credential authorized this" marker, is polluted by actions that had one.

func TestActorClientIDResolution(t *testing.T) {
	cases := []struct {
		name       string
		tokenID    string
		internalID string
		want       string
	}{
		{"third-party azp wins", "sast-people", "sast-link-web", "sast-people"},
		{"console azp passes through", "sast-link-web", "sast-link-web", "sast-link-web"},
		{"empty azp falls back to the console", "", "sast-link-web", "sast-link-web"},
		{"empty azp with unset console stays empty", "", "", ""},
		{"azp is trimmed", " sast-people ", "sast-link-web", "sast-people"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Service{InternalClientID: tc.internalID}
			if got := s.actorClientID(tc.tokenID); got != tc.want {
				t.Fatalf("actorClientID(%q) = %q, want %q", tc.tokenID, got, tc.want)
			}
		})
	}
}

func TestNullableString(t *testing.T) {
	if got := nullableString("x"); got == nil || *got != "x" {
		t.Fatalf("nullableString(\"x\") = %v, want pointer to \"x\"", got)
	}
	if got := nullableString(""); got != nil {
		t.Fatalf("nullableString(\"\") = %v, want nil", got)
	}
}

func TestBuildAuditLogCarriesActorClientID(t *testing.T) {
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	actor := "sast-people"
	withActor, err := buildAuditLog(now, nil, "change_password", "session", nil, &actor, true, 0, "", "", nil)
	if err != nil {
		t.Fatalf("buildAuditLog with actor: %v", err)
	}
	if withActor.ActorClientID == nil || *withActor.ActorClientID != "sast-people" {
		t.Fatalf("ActorClientID = %v, want sast-people", withActor.ActorClientID)
	}

	unauthenticated, err := buildAuditLog(now, nil, "login", "session", nil, nil, true, 0, "", "", nil)
	if err != nil {
		t.Fatalf("buildAuditLog without actor: %v", err)
	}
	if unauthenticated.ActorClientID != nil {
		t.Fatalf("ActorClientID = %v, want nil for an unauthenticated flow", unauthenticated.ActorClientID)
	}
}

func TestChangePasswordAuditRecordsActor(t *testing.T) {
	service := newRegisterService(t)
	audit := service.Audit.(*fakeAudit)

	if _, err := service.ChangePassword(context.Background(), ChangePasswordInput{
		UserID: 42, OldPassword: "secret", NewPassword: "brand-new-password", ActorClientID: "sast-people",
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	entry := lastAuditAction(t, audit, "change_password")
	if entry.ActorClientID == nil || *entry.ActorClientID != "sast-people" {
		t.Fatalf("success audit actor = %v, want sast-people", entry.ActorClientID)
	}

	// The failure path must carry the actor too, or a delegated app's rejected
	// attempt is indistinguishable from nobody's.
	if _, err := service.ChangePassword(context.Background(), ChangePasswordInput{
		UserID: 42, OldPassword: "wrong", NewPassword: "brand-new-password", ActorClientID: "sast-people",
	}); err == nil {
		t.Fatal("ChangePassword with a wrong old password should fail")
	}
	failure := lastAuditAction(t, audit, "change_password")
	if failure.Success == nil || *failure.Success {
		t.Fatalf("failure audit success = %v, want false", failure.Success)
	}
	if failure.ActorClientID == nil || *failure.ActorClientID != "sast-people" {
		t.Fatalf("failure audit actor = %v, want sast-people", failure.ActorClientID)
	}
}

func TestChangePasswordAuditResolvesEmptyActorToConsole(t *testing.T) {
	// newRegisterService sets InternalClientID = "builtin"; an empty azp (a
	// legacy console session token predating the claim) must still name the
	// built-in client rather than NULL.
	service := newRegisterService(t)
	audit := service.Audit.(*fakeAudit)

	if _, err := service.ChangePassword(context.Background(), ChangePasswordInput{
		UserID: 42, OldPassword: "secret", NewPassword: "brand-new-password",
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	entry := lastAuditAction(t, audit, "change_password")
	if entry.ActorClientID == nil || *entry.ActorClientID != "builtin" {
		t.Fatalf("audit actor = %v, want builtin", entry.ActorClientID)
	}
}

func TestUpdateProfileAuditRecordsActor(t *testing.T) {
	service := newRegisterService(t)
	audit := service.Audit.(*fakeAudit)

	if _, err := service.UpdateProfile(context.Background(), UpdateProfileInput{
		UserID: 42, Nickname: stringPtr("新昵称"), ActorClientID: "sast-people",
	}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	entry := lastAuditAction(t, audit, "update_profile")
	if entry.ActorClientID == nil || *entry.ActorClientID != "sast-people" {
		t.Fatalf("audit actor = %v, want sast-people", entry.ActorClientID)
	}
}

func TestLogoutAuditRecordsActor(t *testing.T) {
	service, _, _, _, audit, _ := newTestService(t)
	blacklist := &fakeBlacklist{}
	service.Blacklist = blacklist
	login, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	claims, err := service.JWT.VerifyAccessToken(login.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if _, err := service.Logout(context.Background(), LogoutInput{
		PrincipalJTI: claims.ID, PrincipalUserID: 42, RefreshToken: login.RefreshToken, ActorClientID: "sast-people",
	}); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	entry := lastAuditAction(t, audit, "logout")
	if entry.ActorClientID == nil || *entry.ActorClientID != "sast-people" {
		t.Fatalf("audit actor = %v, want sast-people", entry.ActorClientID)
	}
}

// Unauthenticated flows (login, refresh, registration, password reset) have no
// OAuth credential to attribute; their rows must stay NULL or the V007 contract
// — NULL means no OAuth credential authorized the action — breaks.
func TestUnauthenticatedAuditKeepsActorNil(t *testing.T) {
	service, _, _, _, audit, _ := newTestService(t)
	if _, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "wrong-password"}); err == nil {
		t.Fatal("Login with a wrong password should fail")
	}
	entry := lastAuditAction(t, audit, "login")
	if entry.ActorClientID != nil {
		t.Fatalf("failed login audit actor = %v, want nil", entry.ActorClientID)
	}
}
