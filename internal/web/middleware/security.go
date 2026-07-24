// Package middleware provides Gin middleware for security headers and CORS.
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders applies standard security headers per PRD §7.2.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.Writer.Header()
		header.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Content-Security-Policy", "default-src 'self'")
		header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// CORS returns a middleware that restricts cross-origin access to the configured allowlist.
// An empty list means CORS is disabled (no Access-Control-* headers returned).
func CORS(allowedOrigins []string) gin.HandlerFunc {
	allowMap := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allowMap[strings.TrimSpace(origin)] = struct{}{}
	}
	return func(c *gin.Context) {
		if len(allowMap) == 0 {
			c.Next()
			return
		}
		origin := strings.TrimSpace(c.Request.Header.Get("Origin"))
		if _, ok := allowMap[origin]; !ok {
			c.Next()
			return
		}
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key")
		c.Header("Access-Control-Expose-Headers", "Authorization")
		c.Header("Access-Control-Max-Age", "86400")
		c.Header("Vary", "Origin")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
