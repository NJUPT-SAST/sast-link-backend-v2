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
	adminhandler.RegisterRoutes(router, adminhandler.Handler{}, passthrough, passthrough)

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
		http.MethodGet + " /admin/oauth-clients",
		http.MethodPost + " /admin/oauth-clients",
		http.MethodPut + " /admin/oauth-clients/:id",
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

// The admin routes must be mounted behind both middlewares. Mounting them with only
// authentication would let any logged-in freshman register OAuth clients, which is a
// wiring mistake no unit test inside adminhandler can catch — it stubs its own
// middleware. This asserts the composition root passes both, in order.
func TestAdminRoutesAreGatedByAuthAndRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	var order []string
	authStep := func(c *gin.Context) { order = append(order, "auth"); c.Next() }
	roleStep := func(c *gin.Context) {
		order = append(order, "role")
		c.AbortWithStatus(http.StatusForbidden)
	}
	adminhandler.RegisterRoutes(router, adminhandler.Handler{}, authStep, roleStep)

	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/admin/oauth-clients"},
		{http.MethodPost, "/admin/oauth-clients"},
		{http.MethodPut, "/admin/oauth-clients/5"},
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
		if len(order) != 2 || order[0] != "auth" || order[1] != "role" {
			t.Fatalf("%s %s: middleware order = %v, want [auth role]", route.method, route.path, order)
		}
	}
}

// The role the composition root gates on must be admin. If AdminRole drifted to a
// weaker role, every check above would still pass while the endpoints opened up.
func TestAdminRoleIsAdmin(t *testing.T) {
	if adminhandler.AdminRole != model.UserRoleAdmin {
		t.Fatalf("AdminRole = %q, want admin", adminhandler.AdminRole)
	}
}
