package adminuser

import (
	"context"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

func TestListAuditLogsPassesFiltersThrough(t *testing.T) {
	h := newHarness(t)
	userID := int64(7)
	success := false
	start := testNow.Add(-24 * time.Hour)
	end := testNow

	if _, err := h.service.ListAuditLogs(context.Background(), ListAuditLogsInput{
		Page: 3, PageSize: 10,
		UserID: &userID, Action: "login", Resource: "user",
		Success: &success, StartTime: &start, EndTime: &end,
	}); err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	filter := h.audit.listed
	if filter.UserID == nil || *filter.UserID != userID {
		t.Fatalf("user id filter = %v, want %d", filter.UserID, userID)
	}
	if filter.Action != "login" || filter.Resource != "user" {
		t.Fatalf("action/resource = %q/%q, want login/user", filter.Action, filter.Resource)
	}
	if filter.Success == nil || *filter.Success {
		t.Fatalf("success filter = %v, want false", filter.Success)
	}
	if filter.Limit != 10 || filter.Offset != 20 {
		t.Fatalf("limit/offset = %d/%d, want 10/20", filter.Limit, filter.Offset)
	}
}

// The contract leaves the audit page size open, which means one request could read
// the whole table. It is capped at the same maximum as the user list.
func TestListAuditLogsCapsPageSize(t *testing.T) {
	h := newHarness(t)

	result, err := h.service.ListAuditLogs(context.Background(), ListAuditLogsInput{PageSize: 100000})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if result.PageSize != maxPageSize || h.audit.listed.Limit != maxPageSize {
		t.Fatalf("page size = %d (limit %d), want %d",
			result.PageSize, h.audit.listed.Limit, maxPageSize)
	}
}

func TestListAuditLogsDefaultsPageSize(t *testing.T) {
	h := newHarness(t)

	result, err := h.service.ListAuditLogs(context.Background(), ListAuditLogsInput{})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if result.Page != 1 || result.PageSize != defaultAuditPageSize {
		t.Fatalf("page/size = %d/%d, want 1/%d", result.Page, result.PageSize, defaultAuditPageSize)
	}
}

// An inverted window matches nothing, which would read as "no activity" rather
// than as the mistake it is.
func TestListAuditLogsRejectsInvertedWindow(t *testing.T) {
	h := newHarness(t)
	start := testNow
	end := testNow.Add(-time.Hour)

	_, err := h.service.ListAuditLogs(context.Background(), ListAuditLogsInput{
		StartTime: &start, EndTime: &end,
	})

	assertKind(t, err, KindInvalidInput)
}

// success is NOT NULL with a default of true in V001, so a null can only come from
// a row written before that column existed. Reporting it as false would relabel a
// historical success as a failure.
func TestListAuditLogsTreatsNullSuccessAsTrue(t *testing.T) {
	h := newHarness(t)
	h.audit.listRows = []model.AuditLog{{ID: 1, Action: "login", Resource: "user"}}
	h.audit.total = 1

	result, err := h.service.ListAuditLogs(context.Background(), ListAuditLogsInput{})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(result.Logs) != 1 || !result.Logs[0].Success {
		t.Fatalf("logs = %+v, want one entry reported as successful", result.Logs)
	}
}

func TestListAuditLogsRejectsNonPositiveUserID(t *testing.T) {
	h := newHarness(t)
	userID := int64(0)

	_, err := h.service.ListAuditLogs(context.Background(), ListAuditLogsInput{UserID: &userID})

	assertKind(t, err, KindInvalidInput)
}
