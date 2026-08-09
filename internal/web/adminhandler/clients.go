package adminhandler

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminclient"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
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
// There is no client_id field: the identifier is generated server-side, and because
// the decoder rejects unknown fields, a request trying to choose one is refused
// rather than silently ignored. Same for client_secret.
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
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Clients.CreateClient(c.Request.Context(), adminclient.CreateClientInput{
		ClientName:   req.ClientName,
		ClientType:   req.ClientType,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   req.GrantTypes,
		Scopes:       req.Scopes,
		AdminUserID:  principal.UserID,
		ClientIP:     c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	// The only response in the service that carries a plaintext client_secret, which
	// is shown once and never retrievable again. A 201 is already not cacheable by
	// default, but no-store is what keeps the secret out of an intermediary or browser
	// cache regardless of what a proxy decides the default is — the same reason
	// /oauth/token and /userinfo set it.
	c.Header("Cache-Control", "no-store")
	response.Created(c, createdClientDTO{
		clientDTO:    mapClient(result.Client),
		ClientSecret: result.ClientSecret,
	})
}

// updateClientRequest is a partial update.
//
// Pointers so an omitted field is left alone rather than being read as "clear it".
// client_id / client_secret / client_type / id have no field here, and the strict
// decoder turns an attempt to send one into a 400 — an operator cannot choose
// their own identifier, and client_type is immutable because flipping it without
// reissuing a secret would create a credential-less third_party client. The
// remaining fields are validated in the service.
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
	clientPK, ok := parsePositiveID(c.Param("id"))
	if !ok {
		// A non-numeric or non-positive segment names no client, so it gets the same 404
		// as a missing one rather than a 400 that distinguishes the two.
		response.Error(c, notFound())
		return
	}
	var req updateClientRequest
	if err := decodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Clients.UpdateClient(c.Request.Context(), adminclient.UpdateClientInput{
		ClientPK:     clientPK,
		ClientName:   req.ClientName,
		RedirectURIs: req.RedirectURIs,
		IsActive:     req.IsActive,
		GrantTypes:   req.GrantTypes,
		Scope:        req.Scope,
		AdminUserID:  principal.UserID,
		ClientIP:     c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	message := "客户端信息更新成功"
	if result.RevokedTokens > 0 {
		// Say so: the administrator disabled a client and every session it held was cut,
		// which is a larger consequence than "updated" conveys.
		message = "客户端信息更新成功，已撤销该客户端的全部 Token"
	}
	response.Ok(c, messageResponse{Message: message})
}

// parsePositiveID parses a path segment as a positive primary key.
func parsePositiveID(raw string) (int64, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, false
	}
	value, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || value <= 0 {
		return 0, false
	}
	return value, true
}
