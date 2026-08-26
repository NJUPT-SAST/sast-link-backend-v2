package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

// httpRequestsTotal counts every HTTP request, partitioned by method, route and
// status code. The route label is the registered route pattern (c.FullPath), so
// label cardinality is bounded by the route table rather than by the request
// path.
var httpRequestsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests handled, partitioned by method, route and status code.",
	},
	[]string{"method", "route", "status"},
)

// httpRequestDuration observes HTTP request latency in seconds, partitioned by
// method and route. Status is deliberately not a label here: histogram label
// cardinality multiplies bucketed memory, and latency is a property of the
// route, not of how it answered.
var httpRequestDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "HTTP request latency in seconds, partitioned by method and route.",
		Buckets: prometheus.DefBuckets,
	},
	[]string{"method", "route"},
)

// unmatchedRoute is the route label for requests that matched no route (404s).
// Using a single sentinel instead of the request path keeps label cardinality
// bounded: every unmatched path would otherwise mint its own label set.
const unmatchedRoute = "unmatched"

func init() {
	// The default registry is what promhttp.Handler() exposes on /metrics, so no
	// second registry is constructed or wired in cmd/api.
	prometheus.MustRegister(httpRequestsTotal, httpRequestDuration)
}

// Metrics returns a Gin middleware that records request counts and latency on
// the default Prometheus registry. It must be registered before the route table
// (or at least before the request is handled), because the route label is read
// from c.FullPath() only after c.Next() returns — a route pattern is resolved
// while the handler chain runs, not when the middleware starts.
//
// /metrics is an anonymous scrape surface like /health: it intentionally sits
// outside every auth gate.
func Metrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = unmatchedRoute
		}
		status := strconv.Itoa(c.Writer.Status())
		httpRequestsTotal.WithLabelValues(c.Request.Method, route, status).Inc()
		httpRequestDuration.WithLabelValues(c.Request.Method, route).Observe(time.Since(start).Seconds())
	}
}
