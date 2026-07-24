package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

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
