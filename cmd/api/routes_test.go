package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/adminhandler"
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

	sessionhandler.RegisterRoutes(router, sessionhandler.Handler{}, passthrough)
	oauthhandler.RegisterRoutes(router, oauthhandler.Handler{}, passthrough)
	oauthloginhandler.RegisterRoutes(router, oauthloginhandler.Handler{}, passthrough)
	adminhandler.RegisterRoutes(router, adminhandler.Handler{}, passthrough, passthrough, passthrough)

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
		http.MethodGet + " /oauth/authorize",
		http.MethodPost + " /oauth/authorize/consent",
		http.MethodPost + " /oauth/token",
		http.MethodPost + " /oauth/revoke",
		http.MethodGet + " /.well-known/openid-configuration",
		http.MethodGet + " /.well-known/jwks.json",
		http.MethodGet + " /userinfo",
		http.MethodPost + " /userinfo",
		// Third-party login: the two authorize legs, their callbacks, the
		// login_code exchange, and the two authenticated binding endpoints.
		http.MethodGet + " /oauth/github",
		http.MethodGet + " /oauth/github/callback",
		http.MethodGet + " /oauth/lark",
		http.MethodGet + " /oauth/lark/callback",
		http.MethodPost + " /oauth/exchange-code",
		http.MethodPost + " /user/identities/github",
		http.MethodPost + " /user/identities/lark",
		http.MethodGet + " /admin/oauth-clients",
		http.MethodPost + " /admin/oauth-clients",
		http.MethodPut + " /admin/oauth-clients/:id",
		http.MethodGet + " /admin/users",
		http.MethodGet + " /admin/users/:id",
		http.MethodPut + " /admin/users/:id",
		http.MethodDelete + " /admin/users/:id",
		http.MethodPut + " /admin/users/:id/restore",
		http.MethodGet + " /admin/audit-logs",
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
		http.MethodGet + " /card/:id",
		http.MethodGet + " /user/identities",
		http.MethodPut + " /user/avatar",
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

// Every admin route must be mounted behind authentication and exactly one role
// gate. Mounting one with only authentication would let any logged-in freshman
// reach it, which is a wiring mistake no unit test inside adminhandler can catch —
// it stubs its own middleware. This asserts the composition root passes all three
// in order, and that each route picks the gate its contract calls for: the two
// read-only user endpoints admit a lecturer, everything else is admin-only.
func TestAdminRoutesAreGatedByAuthAndRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	var order []string
	authStep := func(c *gin.Context) { order = append(order, "auth"); c.Next() }
	adminStep := func(c *gin.Context) {
		order = append(order, "admin")
		c.AbortWithStatus(http.StatusForbidden)
	}
	readerStep := func(c *gin.Context) {
		order = append(order, "reader")
		c.AbortWithStatus(http.StatusForbidden)
	}
	adminhandler.RegisterRoutes(router, adminhandler.Handler{}, authStep, adminStep, readerStep)

	for _, route := range []struct {
		method, path, gate string
	}{
		{http.MethodGet, "/admin/oauth-clients", "admin"},
		{http.MethodPost, "/admin/oauth-clients", "admin"},
		{http.MethodPut, "/admin/oauth-clients/5", "admin"},
		// PRD §4.12: reading the directory is open to lecturers, writing is not.
		{http.MethodGet, "/admin/users", "reader"},
		{http.MethodGet, "/admin/users/5", "reader"},
		{http.MethodPut, "/admin/users/5", "admin"},
		{http.MethodDelete, "/admin/users/5", "admin"},
		{http.MethodPut, "/admin/users/5/restore", "admin"},
		{http.MethodGet, "/admin/audit-logs", "admin"},
	} {
		order = nil
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequestWithContext(
			context.Background(), route.method, route.path, nil))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("%s %s: status = %d, want the role gate to reject",
				route.method, route.path, recorder.Code)
		}
		// Authentication must run first: the role check reads the principal it sets.
		if len(order) != 2 || order[0] != "auth" || order[1] != route.gate {
			t.Fatalf("%s %s: middleware order = %v, want [auth %s]",
				route.method, route.path, order, route.gate)
		}
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
