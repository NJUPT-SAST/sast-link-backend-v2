// Package health provides the service health check endpoint.
package health

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler exposes health checks over HTTP.
type Handler struct {
	checks []check
}

type check struct {
	name string
	fn   func() error
}

// New creates a health handler with the provided dependency check functions.
func New(checks map[string]func() error) *Handler {
	h := &Handler{checks: make([]check, 0, len(checks))}
	for name, fn := range checks {
		h.checks = append(h.checks, check{name: name, fn: fn})
	}
	return h
}

// Register adds the health endpoint to the provided router.
func (h *Handler) Register(r *gin.Engine) {
	r.GET("/health", h.Handle)
}

// healthResponse defines a fixed JSON field order for the health endpoint.
type healthResponse struct {
	Status string `json:"status"`
	DB     string `json:"db"`
	Redis  string `json:"redis"`
}

// Handle responds with the aggregated status of all registered checks.
func (h *Handler) Handle(c *gin.Context) {
	resp := healthResponse{
		Status: "ok",
		DB:     "ok",
		Redis:  "ok",
	}
	code := http.StatusOK

	for _, check := range h.checks {
		status := "ok"
		if err := check.fn(); err != nil {
			status = "error"
			resp.Status = "error"
			code = http.StatusInternalServerError
		}

		switch check.name {
		case "db":
			resp.DB = status
		case "redis":
			resp.Redis = status
		}
	}

	c.JSON(code, resp)
}
