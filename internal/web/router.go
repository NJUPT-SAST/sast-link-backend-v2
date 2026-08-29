// Package web wires Gin routes and middleware.
package web

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
)

// NewRouter creates a Gin engine with common middleware registered.
func NewRouter(corsOrigins []string, trustedProxies []string, hstsMaxAge int) (*gin.Engine, error) {
	r := gin.New()
	if err := r.SetTrustedProxies(trustedProxies); err != nil {
		return nil, fmt.Errorf("configure trusted proxies: %w", err)
	}
	// Metrics is the outermost middleware so a recovered panic still lands in it:
	// the status code is read after the chain returns, and gin.Recovery, registered
	// here after it, is what has already written the 500.
	r.Use(middleware.Metrics())
	r.Use(gin.Recovery())
	r.Use(middleware.SecurityHeaders(hstsMaxAge))
	r.Use(middleware.CORS(corsOrigins))
	r.Use(middleware.Logger())
	return r, nil
}
