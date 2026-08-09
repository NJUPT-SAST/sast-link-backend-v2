package adminhandler

import (
	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminuser"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

// statsClientSummary is the OAuth client aggregate shown on the overview.
type statsClientSummary struct {
	Total  int64 `json:"total"`
	Active int64 `json:"active"`
}

// Stats returns the account, client and audit aggregates for the console
// overview dashboard. Composes the three read services; a nil dependency is
// tolerated so the endpoint degrades gracefully rather than 500ing.
func (h Handler) Stats(c *gin.Context) {
	ctx := c.Request.Context()

	users, err := h.Users.Stats(ctx)
	if err != nil {
		response.Error(c, internalError())
		return
	}

	var clients statsClientSummary
	if h.Clients != nil {
		list, err := h.Clients.ListClients(ctx)
		if err != nil {
			response.Error(c, internalError())
			return
		}
		clients.Total = int64(len(list))
		for _, item := range list {
			if item.IsActive {
				clients.Active++
			}
		}
	}

	recent := make([]auditLogDTO, 0, 5)
	if h.AuditLogs != nil {
		if result, err := h.AuditLogs.ListAuditLogs(
			ctx, adminuser.ListAuditLogsInput{Page: 1, PageSize: 5},
		); err == nil {
			for _, entry := range result.Logs {
				recent = append(recent, mapAuditLog(entry))
			}
		}
	}

	response.Ok(c, gin.H{
		"users":   users,
		"clients": clients,
		"audit":   gin.H{"recent": recent},
	})
}
