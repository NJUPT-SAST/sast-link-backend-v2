package adminhandler

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminuser"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

// ListAuditLogs returns a filtered page of audit entries.
func (h Handler) ListAuditLogs(c *gin.Context) {
	page, pageSize, err := parsePaging(c)
	if err != nil {
		response.Error(c, badRequest())
		return
	}
	userID, err := parseOptionalInt64(c.Query("user_id"))
	if err != nil {
		response.Error(c, badRequest())
		return
	}
	success, err := parseOptionalBool(c.Query("success"))
	if err != nil {
		response.Error(c, badRequest())
		return
	}
	startTime, err := parseOptionalTime(c.Query("start_time"))
	if err != nil {
		response.Error(c, badRequest())
		return
	}
	endTime, err := parseOptionalTime(c.Query("end_time"))
	if err != nil {
		response.Error(c, badRequest())
		return
	}

	result, err := h.AuditLogs.ListAuditLogs(c.Request.Context(), adminuser.ListAuditLogsInput{
		Page:      page,
		PageSize:  pageSize,
		UserID:    userID,
		Action:    c.Query("action"),
		Resource:  c.Query("resource"),
		Success:   success,
		StartTime: startTime,
		EndTime:   endTime,
	})
	if err != nil {
		response.Error(c, mapUserServiceError(err))
		return
	}
	items := make([]auditLogDTO, 0, len(result.Logs))
	for _, entry := range result.Logs {
		items = append(items, mapAuditLog(entry))
	}
	response.Ok(c, auditLogListResponse{
		Logs:     items,
		Total:    result.Total,
		Page:     result.Page,
		PageSize: result.PageSize,
	})
}

// parsePaging reads the page window. An absent parameter is zero, which the
// service reads as "use the default"; a present but unparsable one is a 400
// rather than a silent fallback, since a caller that sent page=abc did not mean
// page 1.
func parsePaging(c *gin.Context) (int, int, error) {
	page, err := parseOptionalPositiveInt(c.Query("page"))
	if err != nil {
		return 0, 0, err
	}
	pageSize, err := parseOptionalPositiveInt(c.Query("page_size"))
	if err != nil {
		return 0, 0, err
	}
	return page, pageSize, nil
}

func parseOptionalPositiveInt(raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil || value <= 0 {
		return 0, errInvalidQueryParameter
	}
	return value, nil
}

func parseOptionalInt64(raw string) (*int64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	value, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || value <= 0 {
		return nil, errInvalidQueryParameter
	}
	return &value, nil
}

// parseOptionalBool accepts only "true" and "false". strconv.ParseBool would also
// take "1", "t" and "T", which the contract does not document.
func parseOptionalBool(raw string) (*bool, error) {
	switch strings.TrimSpace(raw) {
	case "":
		return nil, nil
	case "true":
		value := true
		return &value, nil
	case "false":
		value := false
		return &value, nil
	default:
		return nil, errInvalidQueryParameter
	}
}

// parseOptionalTime accepts an RFC 3339 timestamp, which is the ISO 8601 profile
// the contract documents. A value without an offset is rejected rather than
// assumed to be UTC: created_at is timestamptz, so guessing the zone would shift
// the window by hours without saying so.
func parseOptionalTime(raw string) (*time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	value, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return nil, errInvalidQueryParameter
	}
	return &value, nil
}
