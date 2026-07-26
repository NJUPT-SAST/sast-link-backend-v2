package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		header string
		want   string
	}{
		{"Strict-Transport-Security", "max-age=31536000; includeSubDomains"},
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Content-Security-Policy", "default-src 'self'"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
	}
	for _, test := range tests {
		t.Run(test.header, func(t *testing.T) {
			router := gin.New()
			router.Use(SecurityHeaders(31536000))
			router.GET("/test", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK || recorder.Header().Get(test.header) != test.want {
				t.Fatalf("%s = %q, want %q (status=%d)", test.header, recorder.Header().Get(test.header), test.want, recorder.Code)
			}
		})
	}
}

func TestSecurityHeadersPassesOPTIONSDownstream(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(SecurityHeaders(31536000))
	router.OPTIONS("/test", func(c *gin.Context) { c.Status(http.StatusAccepted) })

	request := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/test", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("OPTIONS response = %d, want %d", recorder.Code, http.StatusAccepted)
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers missing on OPTIONS request")
	}
}

func TestCORSRejectsDisallowedOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(CORS([]string{"https://link.sast.fun"}))
	router.GET("/test", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	request.Header.Set("Origin", "https://evil.example.com")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed origin leaked CORS header: %q", recorder.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSRejectsDisallowedPreflightOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(CORS([]string{"https://link.sast.fun"}))

	request := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/test", nil)
	request.Header.Set("Origin", "https://evil.example.com")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden || recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed preflight response=%d ACAO=%q", recorder.Code, recorder.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSAllowsListedOriginAndPreflight(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(CORS([]string{"http://localhost:3000"}))
	router.GET("/test", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	// Normal GET from allowed origin
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	request.Header.Set("Origin", "http://localhost:3000")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Fatalf("allowed origin missing ACAO header")
	}
	if recorder.Header().Get("Vary") != "Origin" {
		t.Fatalf("Vary not set on CORS response")
	}

	// Preflight
	optionsRequest := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/test", nil)
	optionsRequest.Header.Set("Origin", "http://localhost:3000")
	optionsRequest.Header.Set("Access-Control-Request-Method", "POST")
	optionsRecorder := httptest.NewRecorder()
	router.ServeHTTP(optionsRecorder, optionsRequest)

	if optionsRecorder.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", optionsRecorder.Code)
	}
	if optionsRecorder.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatalf("preflight missing Allow-Methods")
	}
}

func TestCORSDisabledWithEmptyList(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(CORS(nil))
	router.GET("/test", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	request.Header.Set("Origin", "https://any.example.com")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	// No CORS headers should be present when disabled
	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("CORS disabled but ACAO present")
	}
}
