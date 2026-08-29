package adminhandler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
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
	listResult     *adminuser.ListUsersResult
	listErr        error
	listInput      adminuser.ListUsersInput
	getResult      *adminuser.UserDetail
	getErr         error
	getID          int64
	getByIDsResult []adminuser.UserDetail
	getByIDsErr    error
	getByIDsInput  adminuser.GetUsersByIDsInput
	updateResult   *adminuser.UpdateUserResult
	updateErr      error
	updateInput    adminuser.UpdateUserInput
	updateCalls    int
	rolesResult    *adminuser.UpdateUserRolesResult
	rolesErr       error
	rolesInput     adminuser.UpdateUserRolesInput
	deleteErr      error
	deleteInput    adminuser.TargetUserInput
	restoreErr     error
	restoreInput   adminuser.TargetUserInput
	statsResult    repository.UserStats
	statsErr       error
	createResult   *adminuser.CreateUserResult
	createErr      error
	createInput    adminuser.CreateUserInput
	createCalls    int
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

func (f *fakeUsers) GetUsersByIDs(
	_ context.Context,
	input adminuser.GetUsersByIDsInput,
) ([]adminuser.UserDetail, error) {
	f.getByIDsInput = input
	if f.getByIDsErr != nil {
		return nil, f.getByIDsErr
	}
	if f.getByIDsResult == nil {
		return []adminuser.UserDetail{}, nil
	}
	return f.getByIDsResult, nil
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

func (f *fakeUsers) UpdateUserRoles(
	_ context.Context,
	input adminuser.UpdateUserRolesInput,
) (*adminuser.UpdateUserRolesResult, error) {
	f.rolesInput = input
	if f.rolesErr != nil {
		return nil, f.rolesErr
	}
	if f.rolesResult == nil {
		return &adminuser.UpdateUserRolesResult{Results: []adminuser.RoleUpdateResult{}}, nil
	}
	return f.rolesResult, nil
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
	if f.statsErr != nil {
		return repository.UserStats{}, f.statsErr
	}
	return f.statsResult, nil
}

func (f *fakeUsers) CreateUser(
	_ context.Context,
	input adminuser.CreateUserInput,
) (*adminuser.CreateUserResult, error) {
	f.createCalls++
	f.createInput = input
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.createResult == nil {
		return &adminuser.CreateUserResult{
			UserID: 3001, LoginEmail: input.LoginEmail, InitialPassword: "secret",
		}, nil
	}
	return f.createResult, nil
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
// injects an admin principal, standing in for RequireAuth plus the role gates.
func newUserRouter(t *testing.T, users UserService, auditLogs AuditLogService) *gin.Engine {
	return newUserRouterWithRole(t, users, auditLogs, "admin")
}

// newUserRouterWithRole is newUserRouter with a configurable principal role, so a
// test can exercise the view a specific role is entitled to.
func newUserRouterWithRole(t *testing.T, users UserService, auditLogs AuditLogService, role string) *gin.Engine {
	t.Helper()
	r := gin.New()
	injectPrincipal := func(c *gin.Context) {
		middleware.SetPrincipal(c, middleware.Principal{
			UserID: testHandlerAdminID, Role: role, JTI: "jti-99",
		})
		c.Next()
	}
	RegisterRoutes(r, Handler{Users: users, AuditLogs: auditLogs}, testGates(injectPrincipal))
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

// The keyword predicate admits phone_number only for an admin principal: a
// lecturer must not be able to probe an account by phone, since the response
// mapping hides the field from them ("admin or hidden" applies to the match the
// same way it applies to the output).
func TestListUsersScopesPhoneKeywordToAdmins(t *testing.T) {
	users := &fakeUsers{}
	router := newUserRouter(t, users, nil)
	doRequest(t, router, http.MethodGet, "/admin/users?keyword=138", "", "")
	if !users.listInput.IncludePhoneColumn {
		t.Fatalf("admin principal: IncludePhoneColumn = false, want true")
	}

	lecturer := &fakeUsers{}
	router = newUserRouterWithRole(t, lecturer, nil, "lecturer")
	doRequest(t, router, http.MethodGet, "/admin/users?keyword=138", "", "")
	if lecturer.listInput.IncludePhoneColumn {
		t.Fatalf("lecturer principal: IncludePhoneColumn = true, want false")
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
		"page_size=101",
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

// The read endpoints are readable by lecturers, but the phone field on them is
// admin-only: an admin sees the stored value (an empty string stays an empty
// string, the true "not filled in" state), any other role sees the field dropped
// entirely — "not disclosed" must not read as "not filled in". qq_number is
// visible to every role. The rule is "admin or hidden" for the phone only, so the
// test asserts the restricted shape for a lecturer rather than pinning the
// allowed set. It covers all three read surfaces: the list, the detail record and
// the batch read, which share the same phone rule but map through different
// functions.
func TestListUsersHidesContactFieldsFromLecturer(t *testing.T) {
	listResult := &adminuser.ListUsersResult{
		Users: []adminuser.UserListItem{{
			ID: 5, Name: "李四", LoginEmail: "b24040102@njupt.edu.cn",
			Role: "member", State: "on_sast", PhoneNumber: "13800138000", QQNumber: "123456",
		}},
		Total: 1, Page: 1, PageSize: 20,
	}
	detail := &adminuser.UserDetail{
		ID: 5, Name: "李四", LoginEmail: "b24040102@njupt.edu.cn",
		Role: "member", State: "on_sast", PhoneNumber: "13800138000", QQNumber: "123456",
	}

	// The lecturer view: the phone field is absent, not null and not an empty
	// string; qq_number rides along like any other field.
	paths := []string{"/admin/users", "/admin/users/5", "/admin/users/batch?ids=5"}
	lecturer := newUserRouterWithRole(t, &fakeUsers{listResult: listResult, getResult: detail, getByIDsResult: []adminuser.UserDetail{*detail}}, nil, "lecturer")
	for _, path := range paths {
		body := doRequest(t, lecturer, http.MethodGet, path, "", "").Body.String()
		if strings.Contains(body, "phone_number") {
			t.Fatalf("lecturer response for %s contains phone_number: %s", path, body)
		}
		if !strings.Contains(body, `"qq_number":"123456"`) {
			t.Fatalf("lecturer response for %s missing qq_number: %s", path, body)
		}
	}

	// The admin view: both values ride along, and an empty string stays an empty
	// string — it is the real "not filled in" marker.
	admin := newUserRouter(t, &fakeUsers{listResult: listResult, getResult: detail, getByIDsResult: []adminuser.UserDetail{*detail}}, nil)
	for _, path := range paths {
		body := doRequest(t, admin, http.MethodGet, path, "", "").Body.String()
		for _, want := range []string{`"phone_number":"13800138000"`, `"qq_number":"123456"`} {
			if !strings.Contains(body, want) {
				t.Fatalf("admin response for %s missing %s: %s", path, want, body)
			}
		}
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
		getResult:      &adminuser.UserDetail{ID: 5, Name: "李四", Role: "member"},
		getByIDsResult: []adminuser.UserDetail{{ID: 5, Name: "李四", Role: "member"}},
	}
	router := newUserRouter(t, users, nil)

	for _, path := range []string{"/admin/users", "/admin/users/5", "/admin/users/batch?ids=5"} {
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

// A provisioning call forwards the body and principal and returns the one-time
// initial password in the response where the administrator can catch it.
func TestCreateUserPassesPrincipalAndFields(t *testing.T) {
	users := &fakeUsers{}
	router := newUserRouter(t, users, nil)

	recorder := doRequest(t, router, http.MethodPost, "/admin/users", "application/json",
		`{"name":"张三","student_id":"B24040525","phone_number":"13800138000",
		  "qq_number":"12345","login_email":"b24040525@njupt.edu.cn",
		  "personal_email":"zhangsan@qq.com","role":"member","state":"retired_sast"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	input := users.createInput
	if input.Name != "张三" || input.StudentID != "B24040525" || input.LoginEmail != "b24040525@njupt.edu.cn" {
		t.Fatalf("provision fields = %+v, want them passed through", input)
	}
	if input.PersonalEmail == nil || *input.PersonalEmail != "zhangsan@qq.com" {
		t.Fatalf("personal_email = %v, want zhangsan@qq.com", input.PersonalEmail)
	}
	if input.Role == nil || *input.Role != "member" || input.State == nil || *input.State != "retired_sast" {
		t.Fatalf("role/state = %v/%v, want member/retired_sast", input.Role, input.State)
	}
	if input.AdminUserID != testHandlerAdminID {
		t.Fatalf("admin id = %d, want %d", input.AdminUserID, testHandlerAdminID)
	}
	var payload struct {
		ID              int64  `json:"id"`
		LoginEmail      string `json:"login_email"`
		InitialPassword string `json:"initial_password"`
	}
	decodeData(t, recorder, &payload)
	if payload.ID != 3001 || payload.InitialPassword != "secret" || payload.LoginEmail != "b24040525@njupt.edu.cn" {
		t.Fatalf("response = %+v, want the provisioned id and the initial password", payload)
	}
}

// The strict decoder protects the provisioning body the same way it protects the
// edit one: an attempt to set a field the endpoint does not define is refused.
func TestCreateUserRejectsUnknownFields(t *testing.T) {
	for _, body := range []string{
		`{"name":"X","student_id":"b1","phone_number":"1","qq_number":"1",
		  "login_email":"x@njupt.edu.cn","password":"hunter2"}`,
		`{"name":"X","student_id":"b1","phone_number":"1","qq_number":"1",
		  "login_email":"x@njupt.edu.cn","email_type":"njupt_email"}`,
	} {
		t.Run(body, func(t *testing.T) {
			users := &fakeUsers{}
			router := newUserRouter(t, users, nil)

			recorder := doRequest(t, router, http.MethodPost, "/admin/users", "application/json", body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for %s", recorder.Code, body)
			}
			if users.createCalls != 0 {
				t.Fatalf("create calls = %d, want the request refused before the service", users.createCalls)
			}
		})
	}
}

// A collision on the primary email or student ID surfaces as 409 with the
// column-naming code, exactly as an update collision does.
func TestCreateUserMapsConflict(t *testing.T) {
	users := &fakeUsers{createErr: &adminuser.Error{
		Kind: adminuser.KindConflict, Code: errcode.CodeEmailAlreadyRegistered, Message: "邮箱已被占用",
	}}
	router := newUserRouter(t, users, nil)

	recorder := doRequest(t, router, http.MethodPost, "/admin/users", "application/json",
		`{"name":"X","student_id":"b1","phone_number":"1","qq_number":"1",
		  "login_email":"x@njupt.edu.cn"}`)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", recorder.Code)
	}
	var body envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if body.Code != errcode.CodeEmailAlreadyRegistered {
		t.Fatalf("code = %d, want CodeEmailAlreadyRegistered", body.Code)
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
	RegisterRoutes(r, Handler{Users: &fakeUsers{}}, testGates(allow))

	for _, testCase := range []struct{ method, path, body string }{
		{http.MethodPost, "/admin/users", `{"name":"X","student_id":"b1","phone_number":"1","qq_number":"1","login_email":"x@njupt.edu.cn"}`},
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

// The batch read passes the parsed id list through and serializes the users in
// the order the service returned them, which is the request order.
func TestGetUsersByIDsPassesListAndReturnsOrder(t *testing.T) {
	users := &fakeUsers{getByIDsResult: []adminuser.UserDetail{
		{ID: 3, Name: "丙", Role: "member"},
		{ID: 1, Name: "甲", Role: "freshman"},
	}}
	router := newUserRouter(t, users, nil)

	recorder := doRequest(t, router, http.MethodGet, "/admin/users/batch?ids=3,1,3,2", "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if got := users.getByIDsInput.IDs; !reflect.DeepEqual(got, []int64{3, 1, 3, 2}) {
		t.Fatalf("ids = %v, want [3 1 3 2] passed through verbatim", got)
	}
	var payload struct {
		Users []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"users"`
	}
	decodeData(t, recorder, &payload)
	if len(payload.Users) != 2 || payload.Users[0].ID != 3 || payload.Users[1].ID != 1 {
		t.Fatalf("users = %+v, want [3 1] in service order", payload.Users)
	}
}

// A blank list, a blank segment or a non-numeric segment is rejected as a whole:
// silently dropping "abc" from "1,abc,2" would return a page the caller cannot
// line up with its input.
func TestGetUsersByIDsRejectsBadLists(t *testing.T) {
	for _, ids := range []string{"", " ", "1,abc,2", "1,,2", "0", "-1", "1,0", "1,-2"} {
		t.Run(ids, func(t *testing.T) {
			users := &fakeUsers{}
			router := newUserRouter(t, users, nil)

			query := ""
			if ids != "" {
				query = "?ids=" + url.QueryEscape(ids)
			}
			recorder := doRequest(t, router, http.MethodGet, "/admin/users/batch"+query, "", "")
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for ids=%q", recorder.Code, ids)
			}
			if users.getByIDsInput.IDs != nil {
				t.Fatalf("service called with %v, want the request refused before it", users.getByIDsInput.IDs)
			}
		})
	}
}

// An empty batch must serialize as [] rather than null, like the list endpoint.
func TestGetUsersByIDsSerializesEmptyAsArray(t *testing.T) {
	users := &fakeUsers{}
	router := newUserRouter(t, users, nil)

	recorder := doRequest(t, router, http.MethodGet, "/admin/users/batch?ids=9", "", "")
	var payload struct {
		Users json.RawMessage `json:"users"`
	}
	decodeData(t, recorder, &payload)
	if string(payload.Users) != "[]" {
		t.Fatalf("users = %s, want []", payload.Users)
	}
}

// The batch role change passes the body and principal through and serializes the
// per-item results.
func TestUpdateUsersRolePassesPrincipalAndBody(t *testing.T) {
	users := &fakeUsers{rolesResult: &adminuser.UpdateUserRolesResult{Results: []adminuser.RoleUpdateResult{
		{ID: 1, Success: true, Role: "member"},
		{ID: 2, Success: false, Reason: "用户不存在"},
	}}}
	router := newUserRouter(t, users, nil)

	recorder := doRequest(t, router, http.MethodPut, "/admin/users", "application/json",
		`{"ids":[1,2],"role":"member"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	input := users.rolesInput
	if !reflect.DeepEqual(input.IDs, []int64{1, 2}) || input.Role != "member" {
		t.Fatalf("input = %+v, want ids [1 2] role member", input)
	}
	if input.AdminUserID != testHandlerAdminID {
		t.Fatalf("admin id = %d, want %d", input.AdminUserID, testHandlerAdminID)
	}
	var payload struct {
		Results []struct {
			ID      int64  `json:"id"`
			Success bool   `json:"success"`
			Role    string `json:"role"`
			Reason  string `json:"reason"`
		} `json:"results"`
	}
	decodeData(t, recorder, &payload)
	if len(payload.Results) != 2 || !payload.Results[0].Success || payload.Results[0].Role != "member" {
		t.Fatalf("results = %+v, want success entry with role", payload.Results)
	}
	if payload.Results[1].Success || payload.Results[1].Reason != "用户不存在" {
		t.Fatalf("failure result = %+v, want reason 用户不存在", payload.Results[1])
	}
	// omitempty keeps the two shapes distinct: no reason on success, no role on failure.
	if strings.Contains(recorder.Body.String(), `"reason":""`) ||
		strings.Contains(recorder.Body.String(), `"role":""`) {
		t.Fatalf("response carries empty optional fields: %s", recorder.Body.String())
	}
}

// The strict decoder protects the batch body the same way it protects the
// single-user one: an unknown field or a trailing value is refused outright
// rather than partially honored.
func TestUpdateUsersRoleRejectsBadBodies(t *testing.T) {
	for _, body := range []string{
		`{"ids":[1,2],"role":"member","state":"on_sast"}`, // unknown field
		`{"ids":[1,2],"role":"member"} trailing`,          // trailing value
	} {
		t.Run(body, func(t *testing.T) {
			users := &fakeUsers{}
			router := newUserRouter(t, users, nil)

			recorder := doRequest(t, router, http.MethodPut, "/admin/users", "application/json", body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for %s", recorder.Code, body)
			}
			if users.rolesInput.IDs != nil {
				t.Fatalf("service called with %+v, want the request refused before it", users.rolesInput)
			}
		})
	}
}

// Missing required fields reach the service untouched: the service is the layer
// that owns the "ids 不能为空" / "role 取值非法" rules, exactly as it owns the
// single-user endpoint's "没有需要更新的字段".
func TestUpdateUsersRolePassesMissingFieldsThrough(t *testing.T) {
	for _, testCase := range []struct {
		name string
		body string
	}{
		{"role absent", `{"ids":[1,2]}`},
		{"ids absent", `{"role":"member"}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			users := &fakeUsers{}
			router := newUserRouter(t, users, nil)

			recorder := doRequest(t, router, http.MethodPut, "/admin/users", "application/json", testCase.body)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 so the service rules on it", recorder.Code)
			}
			if testCase.name == "role absent" && users.rolesInput.Role != "" {
				t.Fatalf("role = %q, want empty to reach the service", users.rolesInput.Role)
			}
			if testCase.name == "ids absent" && len(users.rolesInput.IDs) != 0 {
				t.Fatalf("ids = %v, want empty to reach the service", users.rolesInput.IDs)
			}
		})
	}
}

// A request-level validation failure (bad role, over-cap ids) surfaces as the
// service's 400 with its literal message, like the single-user endpoint.
func TestUpdateUsersRoleMapsServiceError(t *testing.T) {
	users := &fakeUsers{rolesErr: &adminuser.Error{
		Kind: adminuser.KindInvalidInput, Code: errcode.CodeBadRequest, Message: "role 取值非法",
	}}
	router := newUserRouter(t, users, nil)

	recorder := doRequest(t, router, http.MethodPut, "/admin/users", "application/json",
		`{"ids":[1],"role":"boss"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	var body envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if body.Message != "role 取值非法" {
		t.Fatalf("message = %q, want the service's literal", body.Message)
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
