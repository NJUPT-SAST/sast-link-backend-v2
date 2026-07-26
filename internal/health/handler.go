// Package health provides the service health check endpoint.
package health

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Dependency status values reported per check.
const (
	statusOK       = "ok"
	statusError    = "error"
	statusDegraded = "degraded"
)

// optionalChecks names dependencies the service can serve without. Redis only
// backs caches, counters and short-lived state that every flow can rebuild or
// degrade around, so losing it must not mark the instance unhealthy and trigger
// an orchestrator restart loop that cannot fix the outage anyway.
var optionalChecks = map[string]bool{"redis": true}

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
// Only required dependencies affect the overall status and HTTP code; an
// optional dependency reports "degraded" while the service stays healthy.
func (h *Handler) Handle(c *gin.Context) {
	resp := healthResponse{
		Status: statusOK,
		DB:     statusOK,
		Redis:  statusOK,
	}
	code := http.StatusOK

	for _, check := range h.checks {
		status := statusOK
		if err := check.fn(); err != nil {
			if optionalChecks[check.name] {
				status = statusDegraded
			} else {
				status = statusError
				resp.Status = statusError
				code = http.StatusInternalServerError
			}
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
