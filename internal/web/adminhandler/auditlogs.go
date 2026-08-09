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
		Page:          page,
		PageSize:      pageSize,
		UserID:        userID,
		Action:        c.Query("action"),
		Resource:      c.Query("resource"),
		Success:       success,
		ActorClientID: c.Query("actor_client_id"),
		StartTime:     startTime,
		EndTime:       endTime,
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
	page, err := parsePageNumber(c.Query("page"))
	if err != nil {
		return 0, 0, err
	}
	pageSize, err := parseOptionalPositiveInt(c.Query("page_size"))
	if err != nil {
		return 0, 0, err
	}
	return page, pageSize, nil
}

// maxPageNumber bounds a requested page. The service turns page and page_size into
// an offset by multiplying them, which silently overflows for a large enough page:
// 4611686018427387905 wraps to offset 0, so the request would be answered with the
// first page while the response echoed the page number it asked for — a wrong answer
// rather than an error. Other values wrap negative and reach the repository's
// argument guard, surfacing as a 500 where the contract documents a 400.
//
// Rejecting rather than clamping, unlike page_size: a caller asking for page 2^62
// has made a mistake, and answering with some other page would hide it. The bound is
// far past any real page — at the maximum page size of 100 it addresses a hundred
// billion rows.
const maxPageNumber = 1 << 30

func parsePageNumber(raw string) (int, error) {
	value, err := parseOptionalPositiveInt(raw)
	if err != nil {
		return 0, err
	}
	if value > maxPageNumber {
		return 0, errInvalidQueryParameter
	}
	return value, nil
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
