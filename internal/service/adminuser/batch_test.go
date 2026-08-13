package adminuser

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// The batch read must hand the repository the deduplicated id list and return
// the records in request order, with ids that matched nothing absent. Order
// preservation is the point of the endpoint: the caller's list must line up
// with the response.
func TestGetUsersByIDsPreservesRequestOrderAndDropsMissing(t *testing.T) {
	h := newHarness(t)
	first := targetUser(model.UserRoleMember, model.UserStateOnSAST)
	first.ID = 7
	second := targetUser(model.UserRoleFreshman, model.UserStateNJUPTer)
	second.ID = 3
	h.users.findByIDsResult = []model.User{*second, *first} // repository order is unspecified

	users, err := h.service.GetUsersByIDs(context.Background(), GetUsersByIDsInput{
		IDs: []int64{3, 7, 3, 9}, // 3 duplicated, 9 missing
	})
	if err != nil {
		t.Fatalf("GetUsersByIDs: %v", err)
	}
	if got := h.users.findByIDsInput; !slices.Equal(got, []int64{3, 7, 9}) {
		t.Fatalf("repository ids = %v, want [3 7 9] after dedupe", got)
	}
	if len(users) != 2 || users[0].ID != 3 || users[1].ID != 7 {
		t.Fatalf("users = %+v, want [3 7] in request order", users)
	}
	if users[0].Role != string(model.UserRoleFreshman) || users[1].Role != string(model.UserRoleMember) {
		t.Fatalf("roles = %q/%q, want the records' own roles", users[0].Role, users[1].Role)
	}
}

// The batch read rejects the same input shapes at the service boundary that the
// HTTP layer rejects syntactically: empty, over-cap, non-positive.
func TestGetUsersByIDsRejectsBadLists(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		ids     []int64
		message string
	}{
		{"empty", nil, "ids 不能为空"},
		{"over cap", makeIDs(101), "单次最多查询 100 个用户"},
		{"non-positive", []int64{1, 0}, "用户 id 必须为正整数"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t)
			_, err := h.service.GetUsersByIDs(context.Background(), GetUsersByIDsInput{IDs: testCase.ids})
			assertKind(t, err, KindInvalidInput)
			var serviceErr *Error
			if errors.As(err, &serviceErr) && serviceErr.Message != testCase.message {
				t.Fatalf("message = %q, want %q", serviceErr.Message, testCase.message)
			}
			if h.users.findByIDsInput != nil {
				t.Fatalf("repository called with %v, want the request refused before it", h.users.findByIDsInput)
			}
		})
	}
}

func makeIDs(count int) []int64 {
	ids := make([]int64, count)
	for i := range ids {
		ids[i] = int64(i + 1)
	}
	return ids
}

// The cap counts the submitted list, before deduplication: sending one more id
// than the bound, the extra being a duplicate of an existing one, is still over
// the bound — padding with repeats must not steer a batch past its limit.
func TestBatchCapsCountRawInputBeforeDedupe(t *testing.T) {
	h := newHarness(t)
	ids := makeIDs(100)
	ids = append(ids, 1) // a duplicate of an existing id

	_, err := h.service.GetUsersByIDs(context.Background(), GetUsersByIDsInput{IDs: ids})
	assertKind(t, err, KindInvalidInput)
	if h.users.findByIDsInput != nil {
		t.Fatalf("repository called with %v, want the over-cap request refused", h.users.findByIDsInput)
	}

	h2 := newHarness(t)
	ids = makeIDs(500)
	ids = append(ids, 1) // 501 raw, 500 unique: still over the update cap
	_, err = h2.service.UpdateUserRoles(context.Background(), UpdateUserRolesInput{
		IDs:  ids,
		Role: "member",
	})
	assertKind(t, err, KindInvalidInput)
	if h2.users.updateCalls != 0 {
		t.Fatalf("update calls = %d, want the over-cap request refused", h2.users.updateCalls)
	}
}

func TestGetUsersByIDsMapsRepositoryFailure(t *testing.T) {
	h := newHarness(t)
	h.users.findByIDsErr = errors.New("connection refused")

	_, err := h.service.GetUsersByIDs(context.Background(), GetUsersByIDsInput{IDs: []int64{1}})
	assertKind(t, err, KindInternal)
}

// Each id is updated independently through the single-user path, so the batch
// cannot bypass a guard the single-user endpoint honors, and failures are data:
// one bad id does not abort the rest.
func TestUpdateUserRolesAppliesEachIdIndependently(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleFreshman, model.UserStateNJUPTer)
	// First call fails with a not-found, the rest succeed.
	h.users.updateErrs = []error{repository.ErrNotFound, nil, nil}

	result, err := h.service.UpdateUserRoles(context.Background(), UpdateUserRolesInput{
		IDs:         []int64{1, 2, 3},
		Role:        "member",
		AdminUserID: testAdminID,
		ClientIP:    testClientIP,
		UserAgent:   testUserAgent,
	})
	if err != nil {
		t.Fatalf("UpdateUserRoles: %v", err)
	}
	if h.users.updateCalls != 3 {
		t.Fatalf("update calls = %d, want 3 (one per id)", h.users.updateCalls)
	}
	if len(result.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(result.Results))
	}
	if result.Results[0].Success || result.Results[0].Reason != "用户不存在" {
		t.Fatalf("first result = %+v, want a not-found reason", result.Results[0])
	}
	if !result.Results[1].Success || result.Results[1].Role != "member" {
		t.Fatalf("second result = %+v, want success with role member", result.Results[1])
	}
	if result.Results[2].ID != 3 || !result.Results[2].Success {
		t.Fatalf("third result = %+v, want success for id 3", result.Results[2])
	}
	// Every call must have carried the requested role; the fake records the last
	// call's repository input. The batch audit marker is asserted separately, in
	// TestUpdateUserRolesAuditsEachItemWithBatchMarker.
	if h.users.updateInput.Role == nil || *h.users.updateInput.Role != "member" {
		t.Fatalf("last update role = %v, want member", h.users.updateInput.Role)
	}
	if h.users.updatedUserID != 3 {
		t.Fatalf("last update target = %d, want 3", h.users.updatedUserID)
	}
}

// Duplicates collapse before the loop, so one id is never updated twice.
func TestUpdateUserRolesDeduplicatesIDs(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleFreshman, model.UserStateNJUPTer)

	result, err := h.service.UpdateUserRoles(context.Background(), UpdateUserRolesInput{
		IDs:         []int64{5, 5, 5},
		Role:        "member",
		AdminUserID: testAdminID,
	})
	if err != nil {
		t.Fatalf("UpdateUserRoles: %v", err)
	}
	if h.users.updateCalls != 1 {
		t.Fatalf("update calls = %d, want 1 after dedupe", h.users.updateCalls)
	}
	if len(result.Results) != 1 || result.Results[0].ID != 5 {
		t.Fatalf("results = %+v, want the single unique id", result.Results)
	}
}

func TestUpdateUserRolesRejectsBadRequests(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		role    string
		ids     []int64
		message string
	}{
		{"invalid role", "boss", []int64{1}, "role 取值非法"},
		{"empty ids", "member", nil, "ids 不能为空"},
		{"over cap", "member", makeIDs(501), "单次最多更新 500 个用户"},
		{"non-positive id", "member", []int64{1, -1}, "用户 id 必须为正整数"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t)
			_, err := h.service.UpdateUserRoles(context.Background(), UpdateUserRolesInput{
				IDs:  testCase.ids,
				Role: testCase.role,
			})
			assertKind(t, err, KindInvalidInput)
			var serviceErr *Error
			if errors.As(err, &serviceErr) && serviceErr.Message != testCase.message {
				t.Fatalf("message = %q, want %q", serviceErr.Message, testCase.message)
			}
			if h.users.updateCalls != 0 {
				t.Fatalf("update calls = %d, want the request refused before the loop", h.users.updateCalls)
			}
		})
	}
}

// Every item is audited through the shared admin_user_update action, marked as
// a batch so the console can tell a mass promotion from an individual edit.
func TestUpdateUserRolesAuditsEachItemWithBatchMarker(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleFreshman, model.UserStateNJUPTer)

	if _, err := h.service.UpdateUserRoles(context.Background(), UpdateUserRolesInput{
		IDs:         []int64{1, 2},
		Role:        "member",
		AdminUserID: testAdminID,
		ClientIP:    testClientIP,
		UserAgent:   testUserAgent,
	}); err != nil {
		t.Fatalf("UpdateUserRoles: %v", err)
	}
	if len(h.audit.entries) != 2 {
		t.Fatalf("audit entries = %d, want one per id", len(h.audit.entries))
	}
	for _, entry := range h.audit.entries {
		if entry.Action != actionUpdateUser {
			t.Fatalf("action = %q, want %q", entry.Action, actionUpdateUser)
		}
		var detail map[string]any
		if err := json.Unmarshal(entry.Detail, &detail); err != nil {
			t.Fatalf("decode audit detail %s: %v", entry.Detail, err)
		}
		batch, ok := detail["batch"].(bool)
		if !ok || !batch {
			t.Fatalf("audit detail = %v, want batch marker true", detail)
		}
		if !strings.Contains(string(entry.Detail), "role") {
			t.Fatalf("audit detail = %s, want it to name the changed field", entry.Detail)
		}
	}
}

// An untyped repository failure is reported as a generic per-item failure, not
// as a transport error: the caller still gets its other results.
func TestUpdateUserRolesReportsInternalFailuresPerItem(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleFreshman, model.UserStateNJUPTer)
	h.users.updateErr = errors.New("boom")

	result, err := h.service.UpdateUserRoles(context.Background(), UpdateUserRolesInput{
		IDs:  []int64{1},
		Role: "member",
	})
	if err != nil {
		t.Fatalf("UpdateUserRoles: %v", err)
	}
	if len(result.Results) != 1 || result.Results[0].Success ||
		result.Results[0].Reason != "服务器内部错误" {
		t.Fatalf("result = %+v, want a generic internal failure", result.Results)
	}
}

// The protected kinds keep their actionable messages: an administrator learning
// the batch skipped their own id needs to know why. Each case is triggered
// through its real path — the self-role guard, the closed-account check, the
// repository's last-admin guard — not by injecting the error into the fake.
func TestUpdateUserRolesMapsProtectedAndStateKinds(t *testing.T) {
	t.Run("self role change", func(t *testing.T) {
		h := newHarness(t)
		h.users.findResult = targetUser(model.UserRoleFreshman, model.UserStateNJUPTer)
		h.users.findResult.ID = testAdminID

		result, err := h.service.UpdateUserRoles(context.Background(), UpdateUserRolesInput{
			IDs:         []int64{testAdminID},
			Role:        "member",
			AdminUserID: testAdminID,
		})
		if err != nil {
			t.Fatalf("UpdateUserRoles: %v", err)
		}
		if result.Results[0].Success || result.Results[0].Reason != "不可修改自己的角色" {
			t.Fatalf("result = %+v, want the self-role message", result.Results[0])
		}
	})

	t.Run("closed account", func(t *testing.T) {
		h := newHarness(t)
		h.users.findResult = targetUser(model.UserRoleFreshman, model.UserStateDeleted)

		result, err := h.service.UpdateUserRoles(context.Background(), UpdateUserRolesInput{
			IDs:         []int64{testTargetID},
			Role:        "member",
			AdminUserID: testAdminID,
		})
		if err != nil {
			t.Fatalf("UpdateUserRoles: %v", err)
		}
		if result.Results[0].Success || result.Results[0].Reason != "用户已注销，请先恢复后再编辑" {
			t.Fatalf("result = %+v, want the state-conflict message", result.Results[0])
		}
	})

	t.Run("last admin", func(t *testing.T) {
		h := newHarness(t)
		h.users.findResult = targetUser(model.UserRoleAdmin, model.UserStateOnSAST)
		h.users.updateErr = repository.ErrLastAdmin

		result, err := h.service.UpdateUserRoles(context.Background(), UpdateUserRolesInput{
			IDs:         []int64{testTargetID},
			Role:        "member",
			AdminUserID: testAdminID,
		})
		if err != nil {
			t.Fatalf("UpdateUserRoles: %v", err)
		}
		if result.Results[0].Success || result.Results[0].Reason != "系统中至少需要保留一名管理员" {
			t.Fatalf("result = %+v, want the last-admin message", result.Results[0])
		}
	})
}
