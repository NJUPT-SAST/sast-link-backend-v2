// Package departmenthandler serves the public department catalogue. The list is
// static — the enum's membership is decided by the migration and pinned in
// model.Departments — so the handler has no dependencies and the route mounts
// unauthenticated, like /health: an integrator building a label picker or
// rendering 中文 labels needs the catalogue before any user has signed in, and
// the seven department names are public organizational facts, not personal
// data. Keeping the endpoint here (rather than each frontend hardcoding the
// mapping) is what stops integrator copies from drifting the next time the
// enum grows.
package departmenthandler

import (
	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

type departmentsResponse struct {
	Departments []model.DepartmentLabel `json:"departments"`
}

// RegisterRoutes mounts GET /departments.
func RegisterRoutes(r gin.IRouter) {
	r.GET("/departments", list)
}

func list(c *gin.Context) {
	// The catalogue is served from the package-level constant: no allocation
	// beyond the response envelope, nothing to rate limit.
	response.Ok(c, departmentsResponse{Departments: model.Departments})
}
