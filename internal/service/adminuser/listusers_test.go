package adminuser

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

func TestListUsersPassesFiltersThrough(t *testing.T) {
	h := newHarness(t)

	if _, err := h.service.ListUsers(context.Background(), ListUsersInput{
		Page: 2, PageSize: 15,
		Role: string(model.UserRoleLecturer), State: string(model.UserStateOnSAST),
		Department: string(model.DepartmentSoftware),
		StudentID:  "B24040101", Keyword: "张",
	}); err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	filter := h.users.listedFilter
	if filter.Role == nil || *filter.Role != model.UserRoleLecturer {
		t.Fatalf("role filter = %v, want lecturer", filter.Role)
	}
	if filter.State == nil || *filter.State != model.UserStateOnSAST {
		t.Fatalf("state filter = %v, want on_sast", filter.State)
	}
	if filter.Department == nil || *filter.Department != model.DepartmentSoftware {
		t.Fatalf("department filter = %v, want software", filter.Department)
	}
	if filter.StudentID != "B24040101" || filter.Keyword != "张" {
		t.Fatalf("student_id/keyword = %q/%q, want them passed through",
			filter.StudentID, filter.Keyword)
	}
	if filter.Limit != 15 || filter.Offset != 15 {
		t.Fatalf("limit/offset = %d/%d, want 15/15", filter.Limit, filter.Offset)
	}
}

// An unknown enum in a query parameter is a 400 rather than an empty page: the
// caller asked for something the schema cannot express, and an empty result would
// look like "no such users".
func TestListUsersRejectsUnknownEnumFilters(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		input ListUsersInput
	}{
		{"role", ListUsersInput{Role: "superadmin"}},
		{"state", ListUsersInput{State: "retired"}},
		{"department", ListUsersInput{Department: "hardware"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t)
			_, err := h.service.ListUsers(context.Background(), testCase.input)
			assertKind(t, err, KindInvalidInput)
		})
	}
}

// Soft-deleted accounts are listable: the console has to find one in order to
// restore it, so an unfiltered list must not hide them.
func TestListUsersDoesNotFilterDeletedByDefault(t *testing.T) {
	h := newHarness(t)

	if _, err := h.service.ListUsers(context.Background(), ListUsersInput{}); err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if h.users.listedFilter.State != nil {
		t.Fatalf("state filter = %v, want none so closed accounts remain visible",
			h.users.listedFilter.State)
	}
}

func TestListUsersMapsRowsAndPaging(t *testing.T) {
	h := newHarness(t)
	department := model.DepartmentMedia
	h.users.listRows = []repository.AdminUserRow{
		{
			ID: 5, Name: "李四", StudentID: "B24040102",
			LoginEmail: "b24040102@njupt.edu.cn",
			Role:       model.UserRoleMember, State: model.UserStateOnSAST,
			EmailType: model.EmailTypeNJUpt, College: model.CollegeScience,
			Department: &department,
		},
		// A user with no profile row has a null department rather than being hidden.
		{ID: 6, Name: "王五", Role: model.UserRoleFreshman, State: model.UserStateNJUPTer},
	}
	h.users.listTotal = 42

	result, err := h.service.ListUsers(context.Background(), ListUsersInput{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if result.Total != 42 || result.Page != 1 || result.PageSize != 2 {
		t.Fatalf("paging = total %d page %d size %d, want 42/1/2",
			result.Total, result.Page, result.PageSize)
	}
	if len(result.Users) != 2 {
		t.Fatalf("users = %d, want 2", len(result.Users))
	}
	if result.Users[0].Department == nil || *result.Users[0].Department != string(department) {
		t.Fatalf("first department = %v, want media", result.Users[0].Department)
	}
	if result.Users[1].Department != nil {
		t.Fatalf("second department = %v, want nil for a user with no profile row",
			result.Users[1].Department)
	}
}

// An empty page is an empty array, not null: a consumer should not have to handle
// two shapes for "no matches".
func TestListUsersReturnsEmptySliceNotNil(t *testing.T) {
	h := newHarness(t)

	result, err := h.service.ListUsers(context.Background(), ListUsersInput{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if result.Users == nil {
		t.Fatal("users = nil, want an empty slice")
	}
}

// A repository failure must not read as an empty result: an operator seeing zero
// users would conclude the filter matched nothing rather than that the query broke.
func TestListUsersSurfacesRepositoryFailure(t *testing.T) {
	h := newHarness(t)
	h.users.listErr = errors.New("connection reset")

	_, err := h.service.ListUsers(context.Background(), ListUsersInput{})

	assertKind(t, err, KindInternal)
}

func TestListAuditLogsSurfacesRepositoryFailure(t *testing.T) {
	h := newHarness(t)
	h.audit.listErr = errors.New("connection reset")

	_, err := h.service.ListAuditLogs(context.Background(), ListAuditLogsInput{})

	assertKind(t, err, KindInternal)
}

// An unbounded keyword turns one request into three unindexable ILIKE scans plus a
// COUNT(*) over the table, and nothing on this route is rate limited. A keyword wider
// than the widest column it matches cannot match anything anyway.
func TestListUsersRejectsAnOverlongKeyword(t *testing.T) {
	h := newHarness(t)

	_, err := h.service.ListUsers(context.Background(), ListUsersInput{
		Keyword: strings.Repeat("a", validate.MaxNameLength+1),
	})

	assertKind(t, err, KindInvalidInput)
	if h.users.listedFilter.Keyword != "" {
		t.Fatal("the query ran despite the keyword being rejected")
	}
}
