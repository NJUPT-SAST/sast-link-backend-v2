// Package middleware provides Gin middleware for the web layer.
package middleware

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// Logger returns a Gin middleware that logs each request with structured fields.
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		rawQuery := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		if rawQuery != "" {
			path = path + "?" + rawQuery
		}

		traceID := fmt.Sprintf("%016x", start.UnixNano())
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
