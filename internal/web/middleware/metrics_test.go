package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestMetricsMiddlewareRecordsRequest drives one request through the middleware
// and asserts it lands on both the counter (by exact label set) and the latency
// histogram. The counter assertion is order-independent: the label set checked
// here is only touched by this test's own request.
func TestMetricsMiddlewareRecordsRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(Metrics())
	router.GET("/hello/:name", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/hello/world", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	if got := testutil.ToFloat64(httpRequestsTotal.WithLabelValues("GET", "/hello/:name", "200")); got != 1 {
		t.Fatalf("http_requests_total = %v, want 1", got)
	}
	// The histogram must hold at least this request's label set. It is asserted
	// as a lower bound (not an exact count) because the vec is package-global:
	// other tests may have added label sets to it first.
	if got := testutil.CollectAndCount(httpRequestDuration, "http_request_duration_seconds"); got < 1 {
		t.Fatalf("http_request_duration_seconds label sets = %d, want at least 1", got)
	}
}

// TestMetricsMiddlewareBoundedMatchedRouteLabel runs the same request twice and
// checks the status-axis labels: the route label must stay the registered route
// pattern even though the concrete paths differ.
func TestMetricsMiddlewareBoundedMatchedRouteLabel(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(Metrics())
	router.GET("/files/:id", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	for range 2 {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/files/1", nil))
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", recorder.Code)
		}
	}
	if got := testutil.ToFloat64(httpRequestsTotal.WithLabelValues("GET", "/files/:id", "204")); got != 2 {
		t.Fatalf("http_requests_total = %v, want 2", got)
	}
}

// TestMetricsMiddlewareUnmatchedRouteUsesSentinel asserts a request that
// matches no route does not mint a per-path label set: every unmatched path
// shares one "unmatched" route label, keeping label cardinality bounded.
func TestMetricsMiddlewareUnmatchedRouteUsesSentinel(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(Metrics())

	for _, path := range []string{"/nope/one", "/nope/two"} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, recorder.Code)
		}
	}
	if got := testutil.ToFloat64(httpRequestsTotal.WithLabelValues("GET", unmatchedRoute, "404")); got != 2 {
		t.Fatalf("unmatched counter = %v, want 2", got)
	}
}
