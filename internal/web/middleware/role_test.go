package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// roleRequest runs a request through RequireAuth + RequireRole, with dbRole as the
// role stored on the user row and claimRole as the role signed into the token.
func roleRequest(
	t *testing.T,
	dbRole model.UserRole,
	claimRole string,
	allowed ...model.UserRole,
) (*httptest.ResponseRecorder, envelope) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)
	token := signTestToken(t, manager, auth.TokenInput{
		Subject: "42", JTI: "jti-42", Role: claimRole, State: "on_sast", TokenVersion: 7,
		Scopes: []string{"openid"}, TTL: time.Hour, AuthorizedParty: testInternalClientID,
	})
	states := validStates(now)
	states.state.UserRole = dbRole
	authenticator := Authenticator{
		JWT: manager, Tokens: states, Clock: testClock{value: now},
		InternalClientID: testInternalClientID,
	}
	router := gin.New()
	router.GET("/admin/thing", authenticator.RequireAuth(), authenticator.RequireRole(allowed...),
		func(c *gin.Context) {
			principal, _ := PrincipalFrom(c)
			c.JSON(http.StatusOK, envelope{Data: map[string]any{"role": principal.Role}})
		})
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/thing", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	var body envelope
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder, body
}

// The role that decides access is the database's, not the token's. A demoted
// administrator holding a token signed while they were admin must be refused
// immediately; waiting for the token to expire would leave a window in which a
// revoked privilege still works.
func TestRequireRoleUsesDatabaseRoleNotTokenClaim(t *testing.T) {
	recorder, body := roleRequest(t, model.UserRoleMember, "admin", model.UserRoleAdmin)
	if recorder.Code != http.StatusForbidden || body.Code != errcode.CodeForbidden {
		t.Fatalf("response = %d %#v, want 403/%d for a demoted admin", recorder.Code, body, errcode.CodeForbidden)
	}
}

// The inverse: a promotion in the database is honored even though the old token
// still carries the lower role.
func TestRequireRoleHonorsDatabasePromotion(t *testing.T) {
	recorder, body := roleRequest(t, model.UserRoleAdmin, "member", model.UserRoleAdmin)
	if recorder.Code != http.StatusOK || body.Data["role"] != string(model.UserRoleAdmin) {
		t.Fatalf("response = %d %#v, want 200 and the database role", recorder.Code, body)
	}
}

func TestRequireRoleRejectsUnlistedRole(t *testing.T) {
	recorder, body := roleRequest(t, model.UserRoleFreshman, "freshman", model.UserRoleAdmin, model.UserRoleLecturer)
	if recorder.Code != http.StatusForbidden || body.Code != errcode.CodeForbidden {
		t.Fatalf("response = %d %#v, want 403", recorder.Code, body)
	}
}

func TestRequireRoleAdmitsAnyListedRole(t *testing.T) {
	recorder, _ := roleRequest(t, model.UserRoleLecturer, "lecturer", model.UserRoleAdmin, model.UserRoleLecturer)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a listed role", recorder.Code)
	}
}

// An empty allowed set must deny rather than admit everyone: read the other way, a
// wiring slip that dropped the role list would silently open an admin endpoint.
func TestRequireRoleWithNoRolesDeniesEveryone(t *testing.T) {
	recorder, body := roleRequest(t, model.UserRoleAdmin, "admin")
	if recorder.Code != http.StatusForbidden || body.Code != errcode.CodeForbidden {
		t.Fatalf("response = %d %#v, want 403 when no role is allowed", recorder.Code, body)
	}
}

// Without RequireAuth ahead of it there is no Principal. That is a wiring error,
// not a permission decision, so it must surface as 500 rather than as a 403 that
// would look like an ordinary denial.
func TestRequireRoleWithoutAuthenticationIsAnInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authenticator := Authenticator{InternalClientID: testInternalClientID}
	router := gin.New()
	router.GET("/admin/thing", authenticator.RequireRole(model.UserRoleAdmin),
		func(c *gin.Context) { c.Status(http.StatusNoContent) })
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/admin/thing", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when RequireAuth is missing", recorder.Code)
	}
}

// A third-party OAuth token must not reach an admin endpoint. RequireAuth's azp
// gate stops it before RequireRole ever runs, whatever role the user holds.
func TestRequireRoleUnreachableByThirdPartyToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := newTestJWTManager(t, now)
	token := signTestToken(t, manager, auth.TokenInput{
		Subject: "42", JTI: "jti-42", Role: "admin", State: "on_sast", TokenVersion: 7,
		Scopes: []string{"openid"}, TTL: time.Hour, AuthorizedParty: "some-third-party-app",
	})
	states := validStates(now)
	states.state.UserRole = model.UserRoleAdmin
	authenticator := Authenticator{
		JWT: manager, Tokens: states, Clock: testClock{value: now},
		InternalClientID: testInternalClientID,
	}
	router := gin.New()
	reached := false
	router.GET("/admin/thing", authenticator.RequireAuth(), authenticator.RequireRole(model.UserRoleAdmin),
		func(c *gin.Context) { reached = true; c.Status(http.StatusNoContent) })
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/thing", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || reached {
		t.Fatalf("status = %d, handler reached = %v; want 403 and no handler", recorder.Code, reached)
	}
}
