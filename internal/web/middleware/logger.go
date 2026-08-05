// Package middleware provides Gin middleware for the web layer.
package middleware

import (
	"fmt"
	"log/slog"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// traceCounter disambiguates requests that start in the same nanosecond, which
// is routine on one core under a burst; a time-only trace id would collide.
var traceCounter atomic.Uint64

// sensitiveQueryKeys are OAuth one-time credentials or CSRF tokens that must not
// land in request logs. A logged authorization code can be replayed to redeem a
// session; a logged state defeats the CSRF protection it exists to provide.
var sensitiveQueryKeys = map[string]struct{}{
	"code":               {},
	"state":              {},
	"code_challenge":     {},
	"registration_state": {},
	"oauth_state":        {},
	"login_code":         {},
}

// sanitizeRawQuery replaces the values of sensitive query parameters with a
// placeholder. Non-sensitive parameters pass through untouched so debugging
// still has its breadcrumbs.
func sanitizeRawQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "[invalid-query]"
	}
	redacted := false
	for key := range values {
		if _, ok := sensitiveQueryKeys[key]; ok {
			values[key] = []string{"[redacted]"}
			redacted = true
		}
	}
	if !redacted {
		return rawQuery
	}
	return values.Encode()
}

// Logger returns a Gin middleware that logs each request with structured fields.
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// The timing and query-string sanitization below only exist to feed the
		// info-level log line. When the level is above info (the production default
		// is warn), skip them entirely — a discarded log must not cost a clock read
		// and a couple of allocations per request.
		enabled := slog.Default().Enabled(c.Request.Context(), slog.LevelInfo)
		var start time.Time
		if enabled {
			start = time.Now()
		}
		path := c.Request.URL.Path
		rawQuery := c.Request.URL.RawQuery

		c.Next()

		if !enabled {
			return
		}
		latency := time.Since(start)
		if rawQuery != "" {
			path = path + "?" + sanitizeRawQuery(rawQuery)
		}

		traceID := fmt.Sprintf("%016x%06x", start.UnixNano(), traceCounter.Add(1))
		slog.Info(
			"request",
			slog.String("trace_id", traceID),
			slog.String("method", c.Request.Method),
			slog.String("path", path),
			slog.Int("status", c.Writer.Status()),
			slog.Duration("latency", latency),
		)
	}
}
