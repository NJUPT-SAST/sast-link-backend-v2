// Package middleware provides Gin middleware for security headers and CORS.
package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders applies standard security headers per PRD §7.2.
func SecurityHeaders(hstsMaxAge int) gin.HandlerFunc {
	hstsValue := fmt.Sprintf("max-age=%d; includeSubDomains", hstsMaxAge)
	return func(c *gin.Context) {
		header := c.Writer.Header()
		header.Set("Strict-Transport-Security", hstsValue)
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Content-Security-Policy", "default-src 'self'")
		header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}

// CORS returns a middleware that restricts cross-origin access to the configured allowlist.
// An empty list means CORS is disabled (no Access-Control-* headers returned).
func CORS(allowedOrigins []string) gin.HandlerFunc {
	allowMap := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			allowMap[origin] = struct{}{}
		}
	}
	return func(c *gin.Context) {
		if len(allowMap) == 0 {
			c.Next()
			return
		}
		origin := strings.TrimSpace(c.Request.Header.Get("Origin"))
		c.Header("Vary", "Origin")
		if _, ok := allowMap[origin]; !ok {
			if c.Request.Method == http.MethodOptions && origin != "" {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Next()
			return
		}
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key")
		c.Header("Access-Control-Expose-Headers", "Authorization")
		c.Header("Access-Control-Max-Age", "86400")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
