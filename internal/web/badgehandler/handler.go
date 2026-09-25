// Package badgehandler serves the personal-badge management endpoints and the
// public SVG rendering endpoint.
package badgehandler

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/badge"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

// Service is the use-case surface this handler drives.
type Service interface {
	Enable(ctx context.Context, input badge.EnableInput) (*badge.Status, error)
	Disable(ctx context.Context, input badge.DisableInput) error
	Status(ctx context.Context, userID int64) (*badge.Status, error)
	Render(ctx context.Context, input badge.RenderInput) (*badge.RenderResult, error)
}

// Handler serves the badge endpoints.
type Handler struct {
	Service Service
}

// Gates are the middleware the protected management routes are mounted behind.
type Gates struct {
	// RequireAuth authenticates the group (the JWT middleware).
	RequireAuth gin.HandlerFunc
	// RequireReadScope bounds what a scoped token may read; it is a no-op for
	// an internal console token.
	RequireReadScope gin.HandlerFunc
	// RequireWriteScope bounds what a scoped token may change; it is a no-op
	// for an internal console token.
	RequireWriteScope gin.HandlerFunc
}

// ReadScopes is the scope a delegated token must hold to read the badge state,
// matching the other /user read routes.
var ReadScopes = []string{scope.UserRead}

// WriteScopes is the scope a delegated token must hold to toggle the badge,
// matching the other /user write routes.
var WriteScopes = []string{scope.UserWrite}

func RegisterRoutes(r gin.IRouter, h Handler, g Gates) {
	// Panic at boot rather than serve an ungated route: gin would mount a nil
	// middleware and panic on the first request instead.
	if g.RequireAuth == nil || g.RequireReadScope == nil || g.RequireWriteScope == nil {
		panic("badgehandler: every gate in Gates must be set")
	}

	// Every route names a scope gate explicitly so a new route that names none
	// has no scoped-client permission rather than inheriting one.
	protected := r.Group("")
	protected.Use(g.RequireAuth)
	protected.GET("/user/badge", g.RequireReadScope, h.Status)
	protected.POST("/user/badge", g.RequireWriteScope, h.Enable)
	protected.DELETE("/user/badge", g.RequireWriteScope, h.Disable)

	// The public render endpoint: unauthenticated by design — the URL's
	// capability key is the credential, and an img embed cannot carry one.
	// A single :key segment carries the whole path; a trailing .svg is
	// accepted (and stripped) so a shared link reads as an image on platforms
	// that sniff by extension.
	r.GET("/badge/:key", h.ServeSVG)
}

// Status answers GET /user/badge with the caller's sharing state.
func (h Handler) Status(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	status, err := h.Service.Status(c.Request.Context(), principal.UserID)
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, status)
}

// Enable answers POST /user/badge: opt in.
func (h Handler) Enable(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	status, err := h.Service.Enable(c.Request.Context(), badge.EnableInput{
		UserID:        principal.UserID,
		ActorClientID: principal.ClientID,
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Created(c, status)
}

// Disable answers DELETE /user/badge: opt out. Idempotent.
func (h Handler) Disable(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	if err := h.Service.Disable(c.Request.Context(), badge.DisableInput{
		UserID:        principal.UserID,
		ActorClientID: principal.ClientID,
	}); err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, gin.H{"message": "徽标已关闭"})
}

// badgeCacheMaxAge matches the service's render-cache horizon: a viewer (or
// GitHub's camo proxy) may reuse the image this long before revalidating.
const badgeCacheMaxAge = 300

// badgeCSP narrows the global default-src 'self' policy for the SVG response.
// The badge's palette rides an inline <style> element (the auto theme needs a
// prefers-color-scheme media query, which only CSS can express), and the
// avatar rides a data: URI (camo strips external references) — the global
// policy would block both, leaving a blank card. 'none' everywhere else
// keeps the surface tighter than the API default: an SVG served as an image
// has no scripts and loads nothing beyond those two by construction.
const badgeCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"

// ServeSVG answers GET /badge/:key(.svg) with the rendered badge. Unknown or
// closed badges answer 404 with an SVG error card — an img embed must not
// crack — and successful renders carry Cache-Control and a strong ETag so a
// conditional request round-trips without a re-render.
func (h Handler) ServeSVG(c *gin.Context) {
	key := strings.TrimSuffix(c.Param("key"), ".svg")
	result, err := h.Service.Render(c.Request.Context(), badge.RenderInput{
		Key:      key,
		Theme:    c.Query("theme"),
		ClientIP: c.ClientIP(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}

	// Overwrite the security middleware's blanket policy for this image.
	c.Header("Content-Security-Policy", badgeCSP)
	c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d", badgeCacheMaxAge))
	if result.ETag != "" {
		c.Header("ETag", result.ETag)
		if c.GetHeader("If-None-Match") == result.ETag {
			c.Status(http.StatusNotModified)
			return
		}
	}
	status := http.StatusOK
	if result.NotFound {
		status = http.StatusNotFound
	}
	c.Data(status, "image/svg+xml; charset=utf-8", result.SVG)
}
