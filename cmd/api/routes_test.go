package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/adminhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/alumnihandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/oauthhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/oauthloginhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/sessionhandler"
)

// The three handler packages mount onto one engine, so a path claimed by two would
// panic at startup. Registering them together is the only place that shows up.
func TestSessionAndOAuthRoutesCoexist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	passthrough := func(c *gin.Context) { c.Next() }

	sessionhandler.RegisterRoutes(router, sessionhandler.Handler{}, sessionhandler.Gates{
		RequireAuth: passthrough, RequireReadScope: passthrough, RequireWriteScope: passthrough,
		RequireLogoutAuth: passthrough,
	})
	oauthhandler.RegisterRoutes(router, oauthhandler.Handler{}, passthrough)
	oauthloginhandler.RegisterRoutes(router, oauthloginhandler.Handler{}, oauthloginhandler.Gates{
		RequireAuth:       passthrough,
		RequireWriteScope: passthrough,
	})
	adminhandler.RegisterRoutes(router, adminhandler.Handler{}, adminhandler.Gates{
		RequireAuth: passthrough, RequireReadScope: passthrough, RequireWriteScope: passthrough,
		RequireAdmin: passthrough, RequireReader: passthrough,
	})
	alumnihandler.RegisterRoutes(router, alumnihandler.Handler{}, alumnihandler.Gates{
		RequireAuth: passthrough, RequireReadScope: passthrough, RequireWriteScope: passthrough,
		RequireAdmin: passthrough, RequireReader: passthrough,
	})

	registered := make(map[string]bool)
	for _, route := range router.Routes() {
		key := route.Method + " " + route.Path
		if registered[key] {
			t.Fatalf("route %s is registered twice", key)
		}
		registered[key] = true
	}

	// Every endpoint this stage is meant to expose.
	want := []string{
		http.MethodGet + " /.well-known/openid-configuration",
		http.MethodGet + " /.well-known/jwks.json",
		http.MethodGet + " /oauth/authorize",
		http.MethodPost + " /oauth/authorize/consent",
		http.MethodGet + " /oauth/authorize/consent",
		http.MethodPost + " /oauth/token",
		http.MethodPost + " /oauth/revoke",
		http.MethodGet + " /userinfo",
		http.MethodPost + " /userinfo",
		http.MethodGet + " /oauth/grants",
		http.MethodDelete + " /oauth/grants/:client_id",
		// Third-party login: the two authorize legs, their callbacks, the
		// login_code exchange, and the two authenticated binding endpoints.
		http.MethodGet + " /oauth/github",
		http.MethodGet + " /oauth/github/callback",
		http.MethodGet + " /oauth/lark",
		http.MethodGet + " /oauth/lark/callback",
		http.MethodPost + " /oauth/exchange-code",
		http.MethodPost + " /user/identities/github",
		http.MethodPost + " /user/identities/lark",
		// Session surface: login through registration, password recovery, and the
		// self-service read/write endpoints.
		http.MethodPost + " /user/login",
		http.MethodPost + " /auth/refresh",
		http.MethodPost + " /auth/register/send-code",
		http.MethodPost + " /auth/register/verify-code",
		http.MethodPost + " /auth/register",
		http.MethodPost + " /auth/forgot-password/send-code",
		http.MethodPost + " /auth/reset-password",
		http.MethodPost + " /auth/logout",
		http.MethodPost + " /auth/change-password",
		http.MethodGet + " /user/profile",
		http.MethodPut + " /user/profile",
		http.MethodPut + " /user/avatar",
		http.MethodGet + " /user/identities",
		http.MethodPost + " /user/identities/email",
		http.MethodPost + " /user/identities/email/verify",
		http.MethodDelete + " /user/identities/:id",
		http.MethodGet + " /user/devices",
		http.MethodDelete + " /user/devices/:id",
		// Admin console: client registry incl. secret rotation, users incl. the
		// batch pair and provisioning, audit logs and overview stats.
		http.MethodGet + " /admin/oauth-clients",
		http.MethodPost + " /admin/oauth-clients",
		http.MethodPut + " /admin/oauth-clients/:id",
		http.MethodDelete + " /admin/oauth-clients/:id",
		http.MethodPost + " /admin/oauth-clients/:id/rotate-secret",
		http.MethodGet + " /admin/users",
		http.MethodGet + " /admin/users/:id",
		http.MethodPost + " /admin/users",
		http.MethodPut + " /admin/users",
		http.MethodDelete + " /admin/users/:id",
		http.MethodPut + " /admin/users/:id/restore",
		http.MethodGet + " /admin/users/batch",
		http.MethodGet + " /admin/audit-logs",
		http.MethodGet + " /admin/stats",
		// Alumni intake and its console queue.
		http.MethodPost + " /alumni-requests",
		http.MethodGet + " /admin/alumni-requests",
		http.MethodGet + " /admin/alumni-requests/:id",
		http.MethodPost + " /admin/alumni-requests/:id/approve",
		http.MethodPost + " /admin/alumni-requests/:id/reject",
		http.MethodPost + " /admin/alumni-requests/:id/resend-notification",
	}
	for _, route := range want {
		if !registered[route] {
			t.Fatalf("route %s is not registered", route)
		}
	}

	// The session endpoints must still be there: mounting OAuth onto the same engine
	// must not displace them.
	for _, route := range []string{
		http.MethodPost + " /user/login",
		http.MethodPost + " /auth/refresh",
		http.MethodGet + " /user/identities",
		http.MethodPut + " /user/avatar",
		http.MethodGet + " /user/devices",
		http.MethodDelete + " /user/devices/:id",
	} {
		if !registered[route] {
			t.Fatalf("session route %s disappeared", route)
		}
	}
}

// PrincipalFrom must read back what SetPrincipal wrote, since /userinfo
// authenticates inline and would otherwise have no way to publish its principal.
func TestSetPrincipalRoundTrips(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	var seen middleware.Principal
	var found bool
	router.GET("/probe", func(c *gin.Context) {
		middleware.SetPrincipal(c, middleware.Principal{UserID: 7, Scopes: []string{"openid"}})
		seen, found = middleware.PrincipalFrom(c)
		c.Status(http.StatusOK)
	})

	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/probe", nil)
	router.ServeHTTP(httptest.NewRecorder(), request)

	if !found || seen.UserID != 7 || len(seen.Scopes) != 1 {
		t.Fatalf("principal = %+v (found %v), want the value SetPrincipal stored", seen, found)
	}
}

// Every admin route must be mounted behind authentication, exactly one scope gate
// and exactly one role gate. Mounting one with only authentication would let any
// logged-in freshman reach it, and mounting one without a scope gate would let the
// delegated ops client do anything an administrator can — both are wiring mistakes
// no unit test inside adminhandler can catch, since it stubs its own middleware.
//
// This asserts the composition root passes all five in order, and that each route
// picks the gates its contract calls for: the user reads (list, detail, batch)
// admit a lecturer — the phone field, not the endpoint, is what a non-admin role
// loses — everything else is admin-only; reads accept a read-or-write delegated
// scope, writes demand write.
func TestAdminRoutesAreGatedByAuthScopeAndRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	var order []string
	step := func(name string) gin.HandlerFunc {
		return func(c *gin.Context) { order = append(order, name); c.Next() }
	}
	// The role gate aborts, so reaching it proves the whole chain ran in order.
	rejectingStep := func(name string) gin.HandlerFunc {
		return func(c *gin.Context) {
			order = append(order, name)
			c.AbortWithStatus(http.StatusForbidden)
		}
	}
	adminhandler.RegisterRoutes(router, adminhandler.Handler{}, adminhandler.Gates{
		RequireAuth:       step("auth"),
		RequireReadScope:  step("read-scope"),
		RequireWriteScope: step("write-scope"),
		RequireAdmin:      rejectingStep("admin"),
		RequireReader:     rejectingStep("reader"),
	})

	for _, route := range []struct {
		method, path, scopeGate, roleGate string
	}{
		{http.MethodGet, "/admin/oauth-clients", "read-scope", "admin"},
		{http.MethodPost, "/admin/oauth-clients", "write-scope", "admin"},
		{http.MethodPut, "/admin/oauth-clients/5", "write-scope", "admin"},
		// PRD §4.12: the directory list and the detail records are open to lecturers,
		// with the phone field dropped for them inside the mapping; writes are admin-only.
		{http.MethodGet, "/admin/users", "read-scope", "reader"},
		{http.MethodGet, "/admin/users/5", "read-scope", "reader"},
		{http.MethodGet, "/admin/users/batch", "read-scope", "reader"},
		{http.MethodPut, "/admin/users/5", "write-scope", "admin"},
		{http.MethodDelete, "/admin/users/5", "write-scope", "admin"},
		{http.MethodPut, "/admin/users/5/restore", "write-scope", "admin"},
		{http.MethodGet, "/admin/audit-logs", "read-scope", "admin"},
	} {
		order = nil
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequestWithContext(
			context.Background(), route.method, route.path, nil))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("%s %s: status = %d, want the role gate to reject",
				route.method, route.path, recorder.Code)
		}
		// Authentication must run first: every later gate reads the principal it sets.
		want := []string{"auth", route.scopeGate, route.roleGate}
		if !slices.Equal(order, want) {
			t.Fatalf("%s %s: middleware order = %v, want %v",
				route.method, route.path, order, want)
		}
	}
}

// A nil gate must not be mountable. gin accepts a nil HandlerFunc and panics on the
// first request instead, which turns a wiring slip into a runtime failure on a live
// admin endpoint rather than a failure to boot.
func TestRegisterAdminRoutesRejectsIncompleteGates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	passthrough := func(c *gin.Context) { c.Next() }
	full := adminhandler.Gates{
		RequireAuth: passthrough, RequireReadScope: passthrough, RequireWriteScope: passthrough,
		RequireAdmin: passthrough, RequireReader: passthrough,
	}
	for name, mutate := range map[string]func(*adminhandler.Gates){
		"auth":        func(g *adminhandler.Gates) { g.RequireAuth = nil },
		"read scope":  func(g *adminhandler.Gates) { g.RequireReadScope = nil },
		"write scope": func(g *adminhandler.Gates) { g.RequireWriteScope = nil },
		"admin role":  func(g *adminhandler.Gates) { g.RequireAdmin = nil },
		"reader role": func(g *adminhandler.Gates) { g.RequireReader = nil },
	} {
		t.Run(name, func(t *testing.T) {
			gates := full
			mutate(&gates)
			defer func() {
				if recover() == nil {
					t.Fatalf("RegisterRoutes() with a nil %s gate did not panic", name)
				}
			}()
			adminhandler.RegisterRoutes(gin.New(), adminhandler.Handler{}, gates)
		})
	}
}

// The role the composition root gates writes on must be admin. If AdminRole
// drifted to a weaker role, every check above would still pass while the
// endpoints opened up.
func TestAdminRoleIsAdmin(t *testing.T) {
	if adminhandler.AdminRole != model.UserRoleAdmin {
		t.Fatalf("AdminRole = %q, want admin", adminhandler.AdminRole)
	}
}

// The read-only gate must admit exactly admin and lecturer. A drift that added
// member here would open the whole user directory, and the route test above cannot
// see it: it only checks which gate ran, not which roles that gate accepts.
func TestReaderRolesAreAdminAndLecturer(t *testing.T) {
	want := []model.UserRole{model.UserRoleAdmin, model.UserRoleLecturer}
	if len(adminhandler.ReaderRoles) != len(want) {
		t.Fatalf("ReaderRoles = %v, want %v", adminhandler.ReaderRoles, want)
	}
	for index, role := range want {
		if adminhandler.ReaderRoles[index] != role {
			t.Fatalf("ReaderRoles = %v, want %v", adminhandler.ReaderRoles, want)
		}
	}
}

// The console account-request routes carry the same two-dimensional gating as the
// rest of /admin. They differ from the user surface in one place: the whole queue
// — reads included — is admin-only, because a ticket carries an applicant's
// contact details and prospective identity.
func TestAlumniConsoleRoutesAreGatedByAuthScopeAndRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	var order []string
	step := func(name string) gin.HandlerFunc {
		return func(c *gin.Context) { order = append(order, name); c.Next() }
	}
	rejectingStep := func(name string) gin.HandlerFunc {
		return func(c *gin.Context) {
			order = append(order, name)
			c.AbortWithStatus(http.StatusForbidden)
		}
	}
	alumnihandler.RegisterRoutes(router, alumnihandler.Handler{}, alumnihandler.Gates{
		RequireAuth:       step("auth"),
		RequireReadScope:  step("read-scope"),
		RequireWriteScope: step("write-scope"),
		RequireAdmin:      rejectingStep("admin"),
		RequireReader:     rejectingStep("reader"),
	})

	for _, route := range []struct {
		method, path, scopeGate, roleGate string
	}{
		{http.MethodGet, "/admin/alumni-requests", "read-scope", "reader"},
		{http.MethodGet, "/admin/alumni-requests/5", "read-scope", "reader"},
		{http.MethodPost, "/admin/alumni-requests/5/approve", "write-scope", "admin"},
		{http.MethodPost, "/admin/alumni-requests/5/reject", "write-scope", "admin"},
		{http.MethodPost, "/admin/alumni-requests/5/resend-notification", "write-scope", "admin"},
	} {
		order = nil
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequestWithContext(
			context.Background(), route.method, route.path, nil))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("%s %s: status = %d, want the role gate to reject",
				route.method, route.path, recorder.Code)
		}
		want := []string{"auth", route.scopeGate, route.roleGate}
		if !slices.Equal(order, want) {
			t.Fatalf("%s %s: middleware order = %v, want %v",
				route.method, route.path, order, want)
		}
	}
}

// The submission endpoint must NOT sit behind the admin gates: the applicants have
// no account by definition. Its protection is the service's Turnstile check and
// rate limiter, so a gate here would make the intake unreachable — the failure this
// asserts against is someone "fixing" the ungated route by mounting it inside the
// group.
func TestAlumniSubmitRouteIsPublic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	rejecting := func(c *gin.Context) { c.AbortWithStatus(http.StatusForbidden) }
	alumnihandler.RegisterRoutes(router, alumnihandler.Handler{}, alumnihandler.Gates{
		RequireAuth:       rejecting,
		RequireReadScope:  rejecting,
		RequireWriteScope: rejecting,
		RequireAdmin:      rejecting,
		RequireReader:     rejecting,
	})

	recorder := httptest.NewRecorder()
	// No body and a nil service, so this cannot reach a successful submission; the
	// assertion is only that the gates did not reject it.
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(
		context.Background(), http.MethodPost, "/alumni-requests", nil))
	if recorder.Code == http.StatusForbidden {
		t.Fatal("POST /alumni-requests was rejected by an admin gate; the intake would be unreachable")
	}
}

// Same reasoning as the admin gates: a nil gate must fail at boot rather than
// panic on the first request to a live console endpoint.
func TestRegisterAlumniRoutesRejectsIncompleteGates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	passthrough := func(c *gin.Context) { c.Next() }
	full := alumnihandler.Gates{
		RequireAuth: passthrough, RequireReadScope: passthrough, RequireWriteScope: passthrough,
		RequireAdmin: passthrough, RequireReader: passthrough,
	}
	for name, mutate := range map[string]func(*alumnihandler.Gates){
		"auth":        func(g *alumnihandler.Gates) { g.RequireAuth = nil },
		"read scope":  func(g *alumnihandler.Gates) { g.RequireReadScope = nil },
		"write scope": func(g *alumnihandler.Gates) { g.RequireWriteScope = nil },
		"admin role":  func(g *alumnihandler.Gates) { g.RequireAdmin = nil },
		"reader role": func(g *alumnihandler.Gates) { g.RequireReader = nil },
	} {
		t.Run(name, func(t *testing.T) {
			gates := full
			mutate(&gates)
			defer func() {
				if recover() == nil {
					t.Fatalf("RegisterRoutes() with a nil %s gate did not panic", name)
				}
			}()
			alumnihandler.RegisterRoutes(gin.New(), alumnihandler.Handler{}, gates)
		})
	}
}

// The write role must be admin, and the read roles exactly admin and lecturer. The
// route test above only checks which gate ran, not which roles it admits, so a
// drift that added member to ReaderRoles would open the queue invisibly.
func TestAlumniHandlerRolesMatchTheAdminSurface(t *testing.T) {
	if alumnihandler.AdminRole != model.UserRoleAdmin {
		t.Fatalf("AdminRole = %q, want admin", alumnihandler.AdminRole)
	}
	want := []model.UserRole{model.UserRoleAdmin, model.UserRoleLecturer}
	if !slices.Equal(alumnihandler.ReaderRoles, want) {
		t.Fatalf("ReaderRoles = %v, want %v", alumnihandler.ReaderRoles, want)
	}
}
