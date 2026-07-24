package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewRouterHandlesCORSPreflightAfterSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router, err := NewRouter([]string{"https://link.sast.fun"})
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}

	request := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/user/login", nil)
	request.Header.Set("Origin", "https://link.sast.fun")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Headers", "Content-Type")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("preflight response = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if recorder.Header().Get("Access-Control-Allow-Origin") != "https://link.sast.fun" ||
		recorder.Header().Get("Access-Control-Allow-Methods") == "" ||
		recorder.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Fatalf("preflight CORS headers = %#v", recorder.Header())
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("preflight missing security headers")
	}
}

func TestNewRouterDoesNotAllowDisallowedPreflightOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router, err := NewRouter([]string{"https://link.sast.fun"})
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}

	request := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/user/login", nil)
	request.Header.Set("Origin", "https://evil.example.com")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("disallowed preflight status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed preflight origin received ACAO header")
	}
}

func TestNewRouterTrustsOnlyLoopbackProxies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router, err := NewRouter(nil)
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}
	router.GET("/ip", func(c *gin.Context) { c.String(http.StatusOK, c.ClientIP()) })

	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		wantIP     string
	}{
		{name: "untrusted remote ignores forwarded header", remoteAddr: "203.0.113.9:12345", forwarded: "198.51.100.7", wantIP: "203.0.113.9"},
		{name: "IPv4 loopback trusts forwarded header", remoteAddr: "127.0.0.1:12345", forwarded: "198.51.100.7", wantIP: "198.51.100.7"},
		{name: "IPv6 loopback trusts forwarded header", remoteAddr: "[::1]:12345", forwarded: "198.51.100.7", wantIP: "198.51.100.7"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ip", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set("X-Forwarded-For", test.forwarded)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK || recorder.Body.String() != test.wantIP {
				t.Fatalf("response=%d %q, want %q", recorder.Code, recorder.Body.String(), test.wantIP)
			}
		})
	}
}
