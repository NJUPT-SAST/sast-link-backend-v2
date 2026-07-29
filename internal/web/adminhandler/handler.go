// Package adminhandler exposes the administrative console endpoints over HTTP.
package adminhandler

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminclient"
)

// ClientService is the OAuth client registry use cases this handler exposes.
type ClientService interface {
	ListClients(ctx context.Context) ([]adminclient.Client, error)
	CreateClient(ctx context.Context, input adminclient.CreateClientInput) (*adminclient.CreateClientResult, error)
	UpdateClient(ctx context.Context, input adminclient.UpdateClientInput) (*adminclient.UpdateClientResult, error)
}

// Handler serves the admin console endpoints.
type Handler struct {
	Clients ClientService
}

// RegisterRoutes mounts the admin endpoints.
//
// requireAuth must precede requireAdmin: the role check reads the Principal that
// authentication puts in the context. Both are passed in rather than built here so
// the composition root stays the only place that decides how authentication works.
//
// Every route here is behind both. Third-party OAuth tokens cannot reach them at
// all — RequireAuth's azp gate rejects those before the role check runs.
func RegisterRoutes(r gin.IRouter, h Handler, requireAuth, requireAdmin gin.HandlerFunc) {
	admin := r.Group("/admin", requireAuth, requireAdmin)
	admin.GET("/oauth-clients", h.ListClients)
	admin.POST("/oauth-clients", h.CreateClient)
	admin.PUT("/oauth-clients/:id", h.UpdateClient)
}

// AdminRole is the role permitted on these endpoints, exported so the composition
// root cannot silently mount them behind a different one.
const AdminRole = model.UserRoleAdmin
