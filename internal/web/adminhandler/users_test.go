package adminhandler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminuser"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
)

type fakeUsers struct {
	listResult   *adminuser.ListUsersResult
	listErr      error
	listInput    adminuser.ListUsersInput
	getResult    *adminuser.UserDetail
	getErr       error
	getID        int64
	updateResult *adminuser.UpdateUserResult
	updateErr    error
	updateInput  adminuser.UpdateUserInput
	updateCalls  int
	deleteErr    error
	deleteInput  adminuser.TargetUserInput
	restoreErr   error
	restoreInput adminuser.TargetUserInput
}

func (f *fakeUsers) ListUsers(
	_ context.Context,
	input adminuser.ListUsersInput,
) (*adminuser.ListUsersResult, error) {
	f.listInput = input
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listResult == nil {
		return &adminuser.ListUsersResult{Users: []adminuser.UserListItem{}, Page: 1, PageSize: 20}, nil
	}
	return f.listResult, nil
}

func (f *fakeUsers) GetUser(_ context.Context, userID int64) (*adminuser.UserDetail, error) {
	f.getID = userID
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getResult == nil {
		return &adminuser.UserDetail{ID: userID}, nil
	}
	return f.getResult, nil
}

func (f *fakeUsers) UpdateUser(
	_ context.Context,
	input adminuser.UpdateUserInput,
) (*adminuser.UpdateUserResult, error) {
	f.updateCalls++
	f.updateInput = input
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	if f.updateResult == nil {
		return &adminuser.UpdateUserResult{}, nil
	}
	return f.updateResult, nil
}

func (f *fakeUsers) DeleteUser(_ context.Context, input adminuser.TargetUserInput) error {
	f.deleteInput = input
	return f.deleteErr
}

func (f *fakeUsers) RestoreUser(_ context.Context, input adminuser.TargetUserInput) error {
	f.restoreInput = input
	return f.restoreErr
}

func (f *fakeUsers) Stats(_ context.Context) (repository.UserStats, error) {
	return repository.UserStats{}, nil
}

type fakeAuditLogs struct {
	result *adminuser.ListAuditLogsResult
	err    error
	input  adminuser.ListAuditLogsInput
}

func (f *fakeAuditLogs) ListAuditLogs(
	_ context.Context,
	input adminuser.ListAuditLogsInput,
) (*adminuser.ListAuditLogsResult, error) {
	f.input = input
	if f.err != nil {
		return nil, f.err
	}
	if f.result == nil {
		return &adminuser.ListAuditLogsResult{Logs: []adminuser.AuditLogItem{}, Page: 1, PageSize: 50}, nil
	}
	return f.result, nil
}

const testHandlerAdminID int64 = 99

// newUserRouter mounts the admin routes with a stub authentication step that
// injects a principal, standing in for RequireAuth plus the role gates.
func newUserRouter(t *testing.T, users UserService, auditLogs AuditLogService) *gin.Engine {
	t.Helper()
	r := gin.New()
	injectPrincipal := func(c *gin.Context) {
		middleware.SetPrincipal(c, middleware.Principal{
			UserID: testHandlerAdminID, Role: "admin", JTI: "jti-99",
		})
		c.Next()
	}
	allow := func(c *gin.Context) { c.Next() }
	RegisterRoutes(r, Handler{Users: users, AuditLogs: auditLogs}, injectPrincipal, allow, allow)
	return r
}

func TestListUsersPassesQueryParameters(t *testing.T) {
	users := &fakeUsers{}
	router := newUserRouter(t, users, nil)

	query := url.Values{
		"page":       {"3"},
		"page_size":  {"25"},
		"role":       {"lecturer"},
		"state":      {"on_sast"},
		"department": {"software"},
		"student_id": {"B24040101"},
		"keyword":    {"张三"},
	}
	recorder := doRequest(t, router, http.MethodGet, "/admin/users?"+query.Encode(), "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	input := users.listInput
	if input.Page != 3 || input.PageSize != 25 {
		t.Fatalf("page/size = %d/%d, want 3/25", input.Page, input.PageSize)
	}
	if input.Role != "lecturer" || input.State != "on_sast" || input.Department != "software" {
		t.Fatalf("filters = %+v, want them passed through verbatim", input)
	}
	if input.StudentID != "B24040101" || input.Keyword != "张三" {
		t.Fatalf("student_id/keyword = %q/%q, want them passed through",
			input.StudentID, input.Keyword)
	}
}

// A caller that sent page=abc did not mean page 1. Falling back silently would
// return a page they did not ask for and hide the mistake.
//
// The huge values matter for a different reason: the service multiplies page by
// page_size to get an offset, and 4611686018427387905*100 wraps to exactly 0. Left
// unbounded, that request would be answered with the first page while the response
// echoed the page number asked for — a wrong answer with no error. Others wrap
// negative and reach the repository's argument guard, surfacing as a 500 where the
// contract documents a 400.
func TestListUsersRejectsUnparsablePaging(t *testing.T) {
	for _, query := range []string{
		"page=abc", "page=0", "page=-1", "page_size=abc", "page_size=0",
		"page=4611686018427387905", "page=9223372036854775807",
		"page=92233720368547760", "page=9223372036854775808",
	} {
		t.Run(query, func(t *testing.T) {
			users := &fakeUsers{}
			router := newUserRouter(t, users, nil)

			recorder := doRequest(t, router, http.MethodGet, "/admin/users?"+query, "", "")
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for %q", recorder.Code, query)
			}
		})
	}
}

// Absent paging parameters are zero, which the service reads as "use the default".
func TestListUsersAllowsAbsentPaging(t *testing.T) {
	users := &fakeUsers{}
	router := newUserRouter(t, users, nil)

	recorder := doRequest(t, router, http.MethodGet, "/admin/users", "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if users.listInput.Page != 0 || users.listInput.PageSize != 0 {
		t.Fatalf("page/size = %d/%d, want 0/0 so the service applies its defaults",
			users.listInput.Page, users.listInput.PageSize)
	}
}

// An empty page must serialize as [] rather than null, so consumers do not have to
// handle two shapes for "no matches".
func TestListUsersSerializesEmptyPageAsArray(t *testing.T) {
	users := &fakeUsers{listResult: &adminuser.ListUsersResult{Page: 1, PageSize: 20}}
	router := newUserRouter(t, users, nil)

	recorder := doRequest(t, router, http.MethodGet, "/admin/users", "", "")
	var payload struct {
		Users json.RawMessage `json:"users"`
		Total int64           `json:"total"`
	}
	decodeData(t, recorder, &payload)
	if string(payload.Users) != "[]" {
		t.Fatalf("users = %s, want []", payload.Users)
	}
}

// The response must never carry a password hash. adminUserDTO has no such field, so
// this asserts the shape stays that way as the model evolves.
func TestUserResponsesOmitPasswordFields(t *testing.T) {
	users := &fakeUsers{
		listResult: &adminuser.ListUsersResult{
			Users: []adminuser.UserListItem{{
				ID: 5, Name: "李四", LoginEmail: "b24040102@njupt.edu.cn",
				Role: "member", State: "on_sast",
			}},
			Total: 1, Page: 1, PageSize: 20,
		},
		getResult: &adminuser.UserDetail{ID: 5, Name: "李四", Role: "member"},
	}
	router := newUserRouter(t, users, nil)

	for _, path := range []string{"/admin/users", "/admin/users/5"} {
		recorder := doRequest(t, router, http.MethodGet, path, "", "")
		body := recorder.Body.String()
		for _, forbidden := range []string{"password", "PasswordHash", "token_version"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s response contains %q: %s", path, forbidden, body)
			}
		}
	}
}

// A non-numeric or non-positive path segment names no user, so it gets the same 404
// as a missing one rather than a 400 that tells the two apart.
func TestUserRoutesTreatBadIDsAsNotFound(t *testing.T) {
	for _, testCase := range []struct{ method, path, body string }{
		{http.MethodGet, "/admin/users/abc", ""},
		{http.MethodGet, "/admin/users/0", ""},
		{http.MethodPut, "/admin/users/-1", `{"name":"X"}`},
		{http.MethodDelete, "/admin/users/abc", ""},
		{http.MethodPut, "/admin/users/abc/restore", ""},
	} {
		t.Run(testCase.method+" "+testCase.path, func(t *testing.T) {
			users := &fakeUsers{}
			router := newUserRouter(t, users, nil)
			contentType := ""
			if testCase.body != "" {
				contentType = "application/json"
			}

			recorder := doRequest(t, router, testCase.method, testCase.path, contentType, testCase.body)
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", recorder.Code)
			}
			var body envelope
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode envelope: %v", err)
			}
			if body.Code != errcode.CodeUserNotFound {
				t.Fatalf("code = %d, want CodeUserNotFound", body.Code)
			}
		})
	}
}

// The immutable and non-existent properties are protected by the strict decoder:
// an attempt to send one is refused outright instead of being ignored silently.
func TestUpdateUserRejectsUnknownFields(t *testing.T) {
	for _, body := range []string{
		`{"password":"hunter2"}`,
		`{"token_version":9}`,
		`{"name":"X","profile":{"nickname":"y"}}`,
		`{"id":7}`,
	} {
		t.Run(body, func(t *testing.T) {
			users := &fakeUsers{}
			router := newUserRouter(t, users, nil)

			recorder := doRequest(t, router, http.MethodPut, "/admin/users/5", "application/json", body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for %s", recorder.Code, body)
			}
			if users.updateCalls != 0 {
				t.Fatalf("update calls = %d, want the request refused before the service", users.updateCalls)
			}
		})
	}
}

func TestUpdateUserPassesPrincipalAndFields(t *testing.T) {
	users := &fakeUsers{}
	router := newUserRouter(t, users, nil)

	recorder := doRequest(t, router, http.MethodPut, "/admin/users/5", "application/json",
		`{"name":"张三","role":"member","login_email":"x@sast.fun","email_type":"sast_email"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	input := users.updateInput
	if input.UserID != 5 || input.AdminUserID != testHandlerAdminID {
		t.Fatalf("ids = target %d admin %d, want 5 and %d",
			input.UserID, input.AdminUserID, testHandlerAdminID)
	}
	if input.Name == nil || *input.Name != "张三" {
		t.Fatalf("name = %v, want 张三", input.Name)
	}
	if input.Role == nil || *input.Role != "member" {
		t.Fatalf("role = %v, want member", input.Role)
	}
	// An omitted field must stay nil so the service leaves it alone rather than
	// clearing it.
	if input.PhoneNumber != nil || input.State != nil {
		t.Fatalf("omitted fields = %v/%v, want nil", input.PhoneNumber, input.State)
	}
}

// Cutting every session is a larger consequence than "updated" conveys, so the
// message says so.
func TestUpdateUserReportsSessionRevocation(t *testing.T) {
	users := &fakeUsers{updateResult: &adminuser.UpdateUserResult{RevokedSessions: true}}
	router := newUserRouter(t, users, nil)

	recorder := doRequest(t, router, http.MethodPut, "/admin/users/5", "application/json",
		`{"role":"member"}`)
	var payload struct {
		Message string `json:"message"`
	}
	decodeData(t, recorder, &payload)
	if !strings.Contains(payload.Message, "撤销") {
		t.Fatalf("message = %q, want it to mention revocation", payload.Message)
	}
}

func TestDeleteAndRestoreUserPassPrincipal(t *testing.T) {
	users := &fakeUsers{}
	router := newUserRouter(t, users, nil)

	if recorder := doRequest(t, router, http.MethodDelete, "/admin/users/5", "", ""); recorder.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", recorder.Code)
	}
	if users.deleteInput.UserID != 5 || users.deleteInput.AdminUserID != testHandlerAdminID {
		t.Fatalf("delete input = %+v, want target 5 by admin %d",
			users.deleteInput, testHandlerAdminID)
	}
	if recorder := doRequest(t, router, http.MethodPut, "/admin/users/5/restore", "", ""); recorder.Code != http.StatusOK {
		t.Fatalf("restore status = %d, want 200", recorder.Code)
	}
	if users.restoreInput.UserID != 5 || users.restoreInput.AdminUserID != testHandlerAdminID {
		t.Fatalf("restore input = %+v, want target 5 by admin %d",
			users.restoreInput, testHandlerAdminID)
	}
}

// Each service error kind maps to the status its meaning calls for. A protected
// refusal in particular must not read as a role problem, and a state conflict must
// not read as a bad request.
func TestMapUserServiceErrorStatuses(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   int
	}{
		{"invalid input", &adminuser.Error{
			Kind: adminuser.KindInvalidInput, Code: errcode.CodeBadRequest, Message: "role 取值非法",
		}, http.StatusBadRequest, errcode.CodeBadRequest},
		{"not found", &adminuser.Error{
			Kind: adminuser.KindNotFound, Code: errcode.CodeUserNotFound, Message: "用户不存在",
		}, http.StatusNotFound, errcode.CodeUserNotFound},
		{"conflict", &adminuser.Error{
			Kind: adminuser.KindConflict, Code: errcode.CodeStudentIDOccupied, Message: "学号已被占用",
		}, http.StatusConflict, errcode.CodeStudentIDOccupied},
		{"state conflict", &adminuser.Error{
			Kind: adminuser.KindStateConflict, Code: errcode.CodeValidationFailed, Message: "用户已注销",
		}, http.StatusUnprocessableEntity, errcode.CodeValidationFailed},
		{"protected", &adminuser.Error{
			Kind: adminuser.KindProtected, Code: errcode.CodeForbidden, Message: "不可修改自己的角色",
		}, http.StatusForbidden, errcode.CodeForbidden},
		{"internal", &adminuser.Error{
			Kind: adminuser.KindInternal, Code: errcode.CodeInternal, Message: "查询用户失败",
		}, http.StatusInternalServerError, errcode.CodeInternal},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			users := &fakeUsers{updateErr: testCase.err}
			router := newUserRouter(t, users, nil)

			recorder := doRequest(t, router, http.MethodPut, "/admin/users/5",
				"application/json", `{"name":"X"}`)
			if recorder.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, testCase.wantStatus)
			}
			var body envelope
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode envelope: %v", err)
			}
			if body.Code != testCase.wantCode {
				t.Fatalf("code = %d, want %d", body.Code, testCase.wantCode)
			}
		})
	}
}

// An internal failure must not leak its cause. The service's own message for a
// KindInternal is a literal, but the mapper substitutes a generic one anyway so a
// future message carrying a driver error cannot reach the client.
func TestMapUserServiceErrorHidesInternalDetail(t *testing.T) {
	users := &fakeUsers{updateErr: &adminuser.Error{
		Kind:    adminuser.KindInternal,
		Code:    errcode.CodeInternal,
		Message: `pq: password authentication failed for user postgres`,
	}}
	router := newUserRouter(t, users, nil)

	recorder := doRequest(t, router, http.MethodPut, "/admin/users/5", "application/json", `{"name":"X"}`)
	if strings.Contains(recorder.Body.String(), "postgres") {
		t.Fatalf("body leaked the internal cause: %s", recorder.Body.String())
	}
}

// An untyped error is an internal failure rather than a panic or a 200.
func TestMapUserServiceErrorRejectsUntypedError(t *testing.T) {
	users := &fakeUsers{getErr: context.DeadlineExceeded}
	router := newUserRouter(t, users, nil)

	recorder := doRequest(t, router, http.MethodGet, "/admin/users/5", "", "")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
}

func TestListAuditLogsParsesFilters(t *testing.T) {
	auditLogs := &fakeAuditLogs{}
	router := newUserRouter(t, &fakeUsers{}, auditLogs)

	query := url.Values{
		"page":       {"2"},
		"page_size":  {"10"},
		"user_id":    {"7"},
		"action":     {"login"},
		"resource":   {"user"},
		"success":    {"false"},
		"start_time": {"2026-07-01T00:00:00Z"},
		"end_time":   {"2026-07-30T00:00:00Z"},
	}
	recorder := doRequest(t, router, http.MethodGet, "/admin/audit-logs?"+query.Encode(), "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	input := auditLogs.input
	if input.UserID == nil || *input.UserID != 7 {
		t.Fatalf("user_id = %v, want 7", input.UserID)
	}
	if input.Success == nil || *input.Success {
		t.Fatalf("success = %v, want false", input.Success)
	}
	if input.StartTime == nil || !input.StartTime.Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("start_time = %v, want 2026-07-01T00:00:00Z", input.StartTime)
	}
	if input.Action != "login" || input.Resource != "user" {
		t.Fatalf("action/resource = %q/%q, want login/user", input.Action, input.Resource)
	}
}

// Only "true" and "false" are accepted. strconv.ParseBool would also take "1", "t"
// and "T", none of which the contract documents.
func TestListAuditLogsRejectsMalformedFilters(t *testing.T) {
	for _, query := range []string{
		"success=1", "success=yes", "success=TRUE",
		"user_id=abc", "user_id=0", "user_id=-3",
		"start_time=2026-07-01", "start_time=not-a-time",
		// A timestamp with no offset would be silently read as UTC, shifting the window by
		// hours without saying so.
		"start_time=2026-07-01T00:00:00",
	} {
		t.Run(query, func(t *testing.T) {
			auditLogs := &fakeAuditLogs{}
			router := newUserRouter(t, &fakeUsers{}, auditLogs)

			recorder := doRequest(t, router, http.MethodGet, "/admin/audit-logs?"+query, "", "")
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for %q", recorder.Code, query)
			}
		})
	}
}

func TestListAuditLogsSerializesEmptyPageAsArray(t *testing.T) {
	auditLogs := &fakeAuditLogs{result: &adminuser.ListAuditLogsResult{Page: 1, PageSize: 50}}
	router := newUserRouter(t, &fakeUsers{}, auditLogs)

	recorder := doRequest(t, router, http.MethodGet, "/admin/audit-logs", "", "")
	var payload struct {
		Logs json.RawMessage `json:"logs"`
	}
	decodeData(t, recorder, &payload)
	if string(payload.Logs) != "[]" {
		t.Fatalf("logs = %s, want []", payload.Logs)
	}
}

// A missing principal means RequireAuth was not chained ahead of this handler,
// which is a wiring mistake and not something the caller did.
func TestUserWritesWithoutPrincipalAreInternalErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	allow := func(c *gin.Context) { c.Next() }
	RegisterRoutes(r, Handler{Users: &fakeUsers{}}, allow, allow, allow)

	for _, testCase := range []struct{ method, path, body string }{
		{http.MethodPut, "/admin/users/5", `{"name":"X"}`},
		{http.MethodDelete, "/admin/users/5", ""},
		{http.MethodPut, "/admin/users/5/restore", ""},
	} {
		contentType := ""
		if testCase.body != "" {
			contentType = "application/json"
		}
		recorder := doRequest(t, r, testCase.method, testCase.path, contentType, testCase.body)
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("%s %s: status = %d, want 500",
				testCase.method, testCase.path, recorder.Code)
		}
	}
}

func decodeData(t *testing.T, recorder *httptest.ResponseRecorder, destination any) {
	t.Helper()
	var body envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if err := json.Unmarshal(body.Data, destination); err != nil {
		t.Fatalf("decode data: %v", err)
	}
}
