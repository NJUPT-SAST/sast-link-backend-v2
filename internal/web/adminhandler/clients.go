package adminhandler

import (
	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminclient"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/webutil"
)

// ListClients returns every registered OAuth client.
func (h Handler) ListClients(c *gin.Context) {
	clients, err := h.Clients.ListClients(c.Request.Context())
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	dtos := make([]clientDTO, 0, len(clients))
	for _, client := range clients {
		dtos = append(dtos, mapClient(client))
	}
	response.Ok(c, clientListResponse{Clients: dtos})
}

// createClientRequest is a registration submission.
//
// There is no client_id or client_secret field: the identifiers are generated
// server-side, and the strict decoder refuses any request that tries to supply
// one.
type createClientRequest struct {
	ClientName   string   `json:"client_name" binding:"required"`
	ClientType   string   `json:"client_type" binding:"required"`
	RedirectURIs []string `json:"redirect_uris" binding:"required,min=1"`
	GrantTypes   []string `json:"grant_types" binding:"required,min=1"`
	Scopes       []string `json:"scopes" binding:"required,min=1"`
}

// CreateClient registers a new OAuth client.
func (h Handler) CreateClient(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	var req createClientRequest
	if err := webutil.DecodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Clients.CreateClient(c.Request.Context(), adminclient.CreateClientInput{
		ClientName:    req.ClientName,
		ClientType:    req.ClientType,
		RedirectURIs:  req.RedirectURIs,
		GrantTypes:    req.GrantTypes,
		Scopes:        req.Scopes,
		AdminUserID:   principal.UserID,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	// The only response that carries a plaintext client_secret, shown once and
	// never retrievable again; no-store keeps it out of an intermediary or browser
	// cache.
	c.Header("Cache-Control", "no-store")
	response.Created(c, createdClientDTO{
		clientDTO:    mapClient(result.Client),
		ClientSecret: result.ClientSecret,
	})
}

// updateClientRequest is a partial update. Pointers so an omitted field is left
// alone rather than read as "clear it". client_id / client_type have no field
// here, so the strict decoder refuses an attempt to send one; client_type is
// immutable because flipping it without reissuing a secret would create a
// credential-less third_party client.
type updateClientRequest struct {
	ClientName   *string   `json:"client_name"`
	RedirectURIs *[]string `json:"redirect_uris"`
	IsActive     *bool     `json:"is_active"`
	GrantTypes   *[]string `json:"grant_types"`
	Scope        *[]string `json:"scopes"`
}

// UpdateClient applies a partial update to a registration.
func (h Handler) UpdateClient(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	clientPK, ok := web.ParsePositiveID(c.Param("id"))
	if !ok {
		// A non-numeric or non-positive segment names no client, so it gets the same 404
		// as a missing one rather than a 400 that distinguishes the two.
		response.Error(c, notFound())
		return
	}
	var req updateClientRequest
	if err := webutil.DecodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Clients.UpdateClient(c.Request.Context(), adminclient.UpdateClientInput{
		ClientPK:      clientPK,
		ClientName:    req.ClientName,
		RedirectURIs:  req.RedirectURIs,
		IsActive:      req.IsActive,
		GrantTypes:    req.GrantTypes,
		Scope:         req.Scope,
		AdminUserID:   principal.UserID,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	message := "客户端信息更新成功"
	if result.RevokedTokens > 0 {
		// Say so: every session the client held was just cut, a larger consequence
		// than "updated" conveys.
		message = "客户端信息更新成功，已撤销该客户端的全部 Token"
	}
	response.Ok(c, messageResponse{Message: message})
}

// DeleteClient permanently removes a registration. The built-in client is refused
// (403) inside the service: deleting it would lock everyone out of the session
// flow with no console path back. Any other client — capability clients included —
// is removable by any administrator.
func (h Handler) DeleteClient(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	clientPK, ok := web.ParsePositiveID(c.Param("id"))
	if !ok {
		// A non-numeric or non-positive segment names no client, so it gets the same 404
		// as a missing one rather than a 400 that distinguishes the two.
		response.Error(c, notFound())
		return
	}
	result, err := h.Clients.DeleteClient(c.Request.Context(), adminclient.DeleteClientInput{
		ClientPK:      clientPK,
		AdminUserID:   principal.UserID,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	message := "客户端已删除"
	if result.RevokedTokens > 0 {
		// Say so: every session the client held was just cut, a larger consequence
		// than "deleted" conveys.
		message = "客户端已删除，已撤销该客户端的全部 Token"
	}
	response.Ok(c, messageResponse{Message: message})
}

// RotateClientSecret reissues a confidential client's secret. The plaintext is
// returned once and never retrievable again, so the response carries
// Cache-Control: no-store for the same reason CreateClient does.
func (h Handler) RotateClientSecret(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	clientPK, ok := web.ParsePositiveID(c.Param("id"))
	if !ok {
		response.Error(c, notFound())
		return
	}
	result, err := h.Clients.RotateClientSecret(c.Request.Context(), adminclient.RotateClientSecretInput{
		ClientPK:      clientPK,
		AdminUserID:   principal.UserID,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	c.Header("Cache-Control", "no-store")
	response.Ok(c, rotatedClientSecretDTO{ClientID: clientPK, ClientSecret: result.ClientSecret})
}
