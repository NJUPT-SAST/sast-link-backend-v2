package adminuser

import (
	"context"

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
		UserID:    input.UserID,
		Action:    input.Action,
		Resource:  input.Resource,
		Success:   input.Success,
		StartTime: input.StartTime,
		EndTime:   input.EndTime,
		Limit:     pageSize,
		Offset:    (page - 1) * pageSize,
	})
	if err != nil {
		return nil, newError(ErrInternal, "查询审计日志失败", err)
	}
	items := make([]AuditLogItem, 0, len(entries))
	for _, entry := range entries {
		items = append(items, auditLogItem(entry))
	}
	return &ListAuditLogsResult{Logs: items, Total: total, Page: page, PageSize: pageSize}, nil
}
