package adminuser

import (
	"context"
	"log/slog"
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// ListAuditLogs returns a filtered page of audit entries.
//
// A read of the audit trail is not itself audited: recording every query would
// grow the table faster than the queries that inspect it, and PRD §4.13 lists only
// write operations.
func (s Service) ListAuditLogs(ctx context.Context, input ListAuditLogsInput) (*ListAuditLogsResult, error) {
	if s.Audit == nil {
		return nil, newError(ErrInternal, "审计日志仓储未配置", nil)
	}
	if input.UserID != nil && *input.UserID <= 0 {
		return nil, newError(ErrInvalidInput, "user_id 取值非法", nil)
	}
	// An inverted window matches nothing, which reads as "no activity" rather than as
	// the mistake it is.
	if input.StartTime != nil && input.EndTime != nil && input.EndTime.Before(*input.StartTime) {
		return nil, newError(ErrInvalidInput, "end_time 不得早于 start_time", nil)
	}
	page, pageSize := normalizePaging(input.Page, input.PageSize, defaultAuditPageSize)

	entries, total, err := s.Audit.List(ctx, repository.AuditLogFilter{
		UserID:        input.UserID,
		Action:        input.Action,
		Resource:      input.Resource,
		Success:       input.Success,
		ActorClientID: strings.TrimSpace(input.ActorClientID),
		StartTime:     input.StartTime,
		EndTime:       input.EndTime,
		Limit:         pageSize,
		Offset:        (page - 1) * pageSize,
	})
	if err != nil {
		return nil, internalError(ctx, "list admin audit logs", "查询审计日志失败", err)
	}
	items := make([]AuditLogItem, 0, len(entries))
	ids := make([]int64, 0, len(entries))
	for _, entry := range entries {
		items = append(items, auditLogItem(entry))
		if entry.UserID != nil {
			ids = append(ids, *entry.UserID)
		}
	}
	// Attach display names so the console shows who, not just a numeric id.
	// Best effort: a soft-deleted (state = is_deleted) row still returns its name,
	// since the row is still in the table; only a physically deleted row or a
	// failed lookup yields null.
	if s.Users != nil && len(ids) > 0 {
		if names, err := s.Users.NamesByIDs(ctx, ids); err == nil {
			for i := range items {
				if items[i].UserID == nil {
					continue
				}
				if name, ok := names[*items[i].UserID]; ok {
					value := name
					items[i].UserName = &value
				}
			}
		} else {
			// Best-effort must not be silent: without this log an operator cannot tell a
			// genuinely missing user (null name, intended) from a broken lookup.
			slog.WarnContext(ctx, "attach audit user display names",
				"count", len(ids), "error", err)
		}
	}
	return &ListAuditLogsResult{Logs: items, Total: total, Page: page, PageSize: pageSize}, nil
}
