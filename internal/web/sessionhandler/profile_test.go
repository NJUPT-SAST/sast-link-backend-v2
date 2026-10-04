package sessionhandler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
)

func stringPtr(value string) *string { return &value }

func authedRouter(service Service) *gin.Engine {
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuthWith(middleware.Principal{
		UserID: 42, JTI: "jti", ExpiresAt: time.Now().Add(time.Hour),
	})))
	return router
}

// roleRouter mounts the profile routes behind a principal carrying an explicit
// role, the value the live database row (not the token claim) produced.
func roleRouter(service Service, role string) *gin.Engine {
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuthWith(middleware.Principal{
		UserID: 42, JTI: "jti", ExpiresAt: time.Now().Add(time.Hour), Role: role,
	})))
	return router
}

func doJSON(router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestUpdateProfileReturnsMessageAndUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{updateProfileResult: &session.UpdateProfileResult{
		Profile: session.UserProfileDTO{
			ID: 42, Name: "张三", LoginEmail: "pt@sast.fun", Role: "member",
			State: "on_sast", EmailType: "sast_email", College: "计算机学院、软件学院、网络空间安全学院",
			Profile: &session.ProfileDetailDTO{Nickname: stringPtr("新昵称")},
		},
		ChangedFields: []string{"name", "nickname"},
	}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodPut, "/user/profile", `{"name":"张三","nickname":"新昵称"}`)

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	data := body.Data.(map[string]any)
	if data["message"] != "个人信息更新成功" {
		t.Fatalf("message = %#v, want 个人信息更新成功", data["message"])
	}
	user := data["user"].(map[string]any)
	if user["id"] != float64(42) || user["name"] != "张三" {
		t.Fatalf("user = %#v", user)
	}
	if service.updateProfileInput.UserID != 42 {
		t.Fatalf("user id = %d, want the principal's 42", service.updateProfileInput.UserID)
	}
	if got := service.updateProfileInput.Name; got == nil || *got != "张三" {
		t.Fatalf("name input = %v", got)
	}
}

// An absent key must arrive as nil and an explicit empty string as a pointer to
// "": the service relies on that distinction to tell "leave unchanged" from
// "clear this field".
func TestUpdateProfileDistinguishesAbsentFromEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{updateProfileResult: &session.UpdateProfileResult{}}
	router := authedRouter(service)
	if recorder := doJSON(router, http.MethodPut, "/user/profile", `{"intro":""}`); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	input := service.updateProfileInput
	if input.Intro == nil || *input.Intro != "" {
		t.Fatalf("intro = %v, want pointer to empty string", input.Intro)
	}
	if input.Nickname != nil {
		t.Fatalf("nickname = %v, want nil for an absent key", *input.Nickname)
	}
}

// The department gate is decided in the service on the principal's live role,
// so the handler's one job is forwarding it untouched: a manager's request
// carries "manager" into the service, and a principal with no role resolves
// to the empty string rather than some defaulted value.
func TestUpdateProfileForwardsPrincipalRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{updateProfileResult: &session.UpdateProfileResult{}}
	if recorder := doJSON(roleRouter(service, "manager"), http.MethodPut, "/user/profile", `{"department":"software"}`); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if service.updateProfileInput.Role != "manager" {
		t.Fatalf("role = %q, want the principal's manager", service.updateProfileInput.Role)
	}

	service = &fakeService{updateProfileResult: &session.UpdateProfileResult{}}
	if recorder := doJSON(authedRouter(service), http.MethodPut, "/user/profile", `{"intro":"新介绍"}`); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if service.updateProfileInput.Role != "" {
		t.Fatalf("role = %q, want empty when the principal carries none", service.updateProfileInput.Role)
	}
}

// Unknown fields are rejected rather than silently dropped, so a client that
// misspells login_email does not believe it changed a protected column.
// student_id joined that class when the self-service edit was removed: the
// strict decoder answers the key with 400 instead of the field quietly
// changing (or being ignored) — changing a student ID is an administrator's
// correction.
func TestUpdateProfileRejectsUnknownFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{updateProfileResult: &session.UpdateProfileResult{}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodPut, "/user/profile", `{"login_email":"attacker@sast.fun", "student_id":"B24040999"}`)

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusBadRequest || body.Code != errcode.CodeBadRequest {
		t.Fatalf("response = %d %#v, want 400/%d", recorder.Code, body, errcode.CodeBadRequest)
	}
	if service.updateProfileCalls != 0 {
		t.Fatalf("service called %d times, want 0", service.updateProfileCalls)
	}
}
