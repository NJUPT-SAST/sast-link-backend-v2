package adminhandler

import (
	"log/slog"

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
// overview dashboard. Users is the authoritative leg and must be wired; Clients
// and AuditLogs are optional and degrade to zeroed aggregates when nil, so the
// endpoint stays up rather than 500ing over a best-effort view.
//
// The clients and audit legs carry the two technical surfaces (the OAuth
// registry and the audit trail), so a manager — admitted to the overview for
// its account aggregates — gets the users leg only: the keys are absent from
// the response entirely, the same "not disclosed rather than empty" posture
// the phone field uses.
func (h Handler) Stats(c *gin.Context) {
	ctx := c.Request.Context()

	users, err := h.Users.Stats(ctx)
	if err != nil {
		// The 500 carries no cause, so the reason must land in the logs here or it
		// is gone entirely.
		slog.ErrorContext(ctx, "load overview user stats", "error", err)
		response.Error(c, internalError())
		return
	}

	if principalRole(c) != string(AdminRole) {
		response.Ok(c, gin.H{"users": users})
		return
	}

	var clients statsClientSummary
	if h.Clients != nil {
		// Two integers from one aggregate: decoding every registration whole
		// (redirect URIs, grant types, scopes) only to count them grew with the
		// registry for no reason.
		summary, err := h.Clients.CountClients(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "load overview client stats", "error", err)
			response.Error(c, internalError())
			return
		}
		clients.Total = summary.Total
		clients.Active = summary.Active
	}

	recent := make([]auditLogDTO, 0, 5)
	if h.AuditLogs != nil {
		if result, err := h.AuditLogs.ListAuditLogs(
			ctx, adminuser.ListAuditLogsInput{Page: 1, PageSize: 5},
		); err == nil {
			for _, entry := range result.Logs {
				recent = append(recent, mapAuditLog(entry))
			}
		} else {
			// Fail-open by design, but the overview must not silently read as "no audit
			// activity": an empty recent list could be a real empty table or a broken
			// query, so log the failure.
			slog.WarnContext(ctx, "load overview audit recent",
				"error", err)
		}
	}

	response.Ok(c, gin.H{
		"users":   users,
		"clients": clients,
		"audit":   gin.H{"recent": recent},
	})
}
