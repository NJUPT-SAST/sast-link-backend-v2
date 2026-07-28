package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/oauthhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/sessionhandler"
)

// The two handler packages mount onto one engine, so a path claimed by both would
// panic at startup. Registering them together is the only place that shows up.
func TestSessionAndOAuthRoutesCoexist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	passthrough := func(c *gin.Context) { c.Next() }

	sessionhandler.RegisterRoutes(router, sessionhandler.Handler{}, passthrough)
	oauthhandler.RegisterRoutes(router, oauthhandler.Handler{}, passthrough)

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
