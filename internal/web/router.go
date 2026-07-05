// Package web wires Gin routes and middleware.
package web

import (
	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
)

// NewRouter creates a Gin engine with common middleware registered.
func NewRouter() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.Logger())
	return r
}
