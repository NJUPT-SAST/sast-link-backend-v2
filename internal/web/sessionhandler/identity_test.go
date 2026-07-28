package sessionhandler

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
)

func TestListIdentitiesReturnsArray(t *testing.T) {
	gin.SetMode(gin.TestMode)
	created := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	service := &fakeService{listIdentitiesResult: &session.ListIdentitiesResult{
		Identities: []session.IdentityDTO{
			{ID: 1, Provider: "github", ProviderID: "145339646", CreatedAt: created, UpdatedAt: created},
			{ID: 3, Provider: "other_mail", ProviderID: "me@qq.com", CreatedAt: created, UpdatedAt: created},
		},
	}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodGet, "/user/identities", "")

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	identities := body.Data.(map[string]any)["identities"].([]any)
	if len(identities) != 2 {
		t.Fatalf("identities = %#v, want 2", identities)
	}
	first := identities[0].(map[string]any)
	if first["provider"] != "github" || first["provider_id"] != "145339646" {
		t.Fatalf("first identity = %#v", first)
	}
	if service.listIdentitiesInput.UserID != 42 {
		t.Fatalf("user id = %d, want 42", service.listIdentitiesInput.UserID)
	}
}

// An empty binding list must serialize as [] rather than null, so clients can
// iterate the field unconditionally.
func TestListIdentitiesRendersEmptyArray(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{listIdentitiesResult: &session.ListIdentitiesResult{}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodGet, "/user/identities", "")

	if !strings.Contains(recorder.Body.String(), `"identities":[]`) {
		t.Fatalf("body = %s, want an empty JSON array", recorder.Body.String())
	}
}

func TestUnbindIdentityPassesPathIDAndPassword(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{unbindIdentityResult: &session.UnbindIdentityResult{
		Provider: "other_mail", ProviderID: "me@qq.com",
	}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodDelete, "/user/identities/12", `{"password":"secret"}`)

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	if data := body.Data.(map[string]any); data["message"] != "解绑成功" {
		t.Fatalf("data = %#v", data)
	}
	input := service.unbindIdentityInput
	if input.UserID != 42 || input.IdentityID != 12 || input.Password != "secret" {
		t.Fatalf("input = %+v", input)
	}
}

func TestUnbindIdentityRequiresPassword(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodDelete, "/user/identities/12", `{}`)

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusBadRequest || body.Code != errcode.CodeBadRequest {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	if service.unbindIdentityCalls != 0 {
		t.Fatalf("service called %d times, want 0", service.unbindIdentityCalls)
	}
}

// A non-numeric path segment names no binding the caller could own, so it answers
// 404xx like somebody else's ID rather than a 400 that confirms the difference.
func TestUnbindIdentityRejectsMalformedPathID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, raw := range []string{"abc", "0", "-1", "1.5", "%2B12"} {
		t.Run(raw, func(t *testing.T) {
			service := &fakeService{}
			router := authedRouter(service)
			recorder := doJSON(router, http.MethodDelete, "/user/identities/"+raw, `{"password":"secret"}`)

			body := decodeBody(t, recorder)
			if recorder.Code != http.StatusNotFound || body.Code != errcode.CodeNotFound {
				t.Fatalf("response = %d %#v, want 404/%d", recorder.Code, body, errcode.CodeNotFound)
			}
			if service.unbindIdentityCalls != 0 {
				t.Fatalf("service called %d times, want 0", service.unbindIdentityCalls)
			}
		})
	}
}

func TestUnbindIdentityMapsNotFoundKind(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{unbindIdentityErr: &session.Error{
		Kind: session.KindNotFound, Code: errcode.CodeNotFound, Message: "绑定记录不存在",
	}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodDelete, "/user/identities/12", `{"password":"secret"}`)

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusNotFound || body.Code != errcode.CodeNotFound {
		t.Fatalf("response = %d %#v, want 404/%d", recorder.Code, body, errcode.CodeNotFound)
	}
}

// mapServiceError rebuilds the message from the code rather than forwarding
// serviceErr.Message, which is deliberate — many service messages are internal
// diagnostics. The cost is that a code with no case silently degrades to its Kind
// default, so the reason the client needs is the thing that goes missing.
func TestUnbindIdentityKeepsSpecificMessages(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for name, testCase := range map[string]struct {
		err     *session.Error
		status  int
		code    int
		message string
	}{
		"last login method": {
			err:     &session.Error{Kind: session.KindValidationFailed, Code: errcode.CodeValidationFailed, Message: "不能解绑唯一的登录方式"},
			status:  http.StatusUnprocessableEntity,
			code:    errcode.CodeValidationFailed,
			message: "不能解绑唯一的登录方式",
		},
		"missing binding": {
			err:     &session.Error{Kind: session.KindNotFound, Code: errcode.CodeNotFound, Message: "绑定记录不存在"},
			status:  http.StatusNotFound,
			code:    errcode.CodeNotFound,
			message: "绑定记录不存在",
		},
	} {
		t.Run(name, func(t *testing.T) {
			router := authedRouter(&fakeService{unbindIdentityErr: testCase.err})
			recorder := doJSON(router, http.MethodDelete, "/user/identities/12", `{"password":"secret"}`)

			body := decodeBody(t, recorder)
			if recorder.Code != testCase.status || body.Code != testCase.code {
				t.Fatalf("response = %d %#v, want %d/%d", recorder.Code, body, testCase.status, testCase.code)
			}
			if body.Message != testCase.message {
				t.Fatalf("message = %q, want %q", body.Message, testCase.message)
			}
		})
	}
}

// Both ways to get a 404 out of unbind must read the same, so a caller cannot
// tell a malformed ID from a binding that is missing or owned by someone else.
func TestUnbindIdentityNotFoundMessagesMatch(t *testing.T) {
	gin.SetMode(gin.TestMode)

	malformed := decodeBody(t, doJSON(
		authedRouter(&fakeService{}),
		http.MethodDelete, "/user/identities/abc", `{"password":"secret"}`,
	))
	fromService := decodeBody(t, doJSON(
		authedRouter(&fakeService{unbindIdentityErr: &session.Error{
			Kind: session.KindNotFound, Code: errcode.CodeNotFound, Message: "绑定记录不存在",
		}}),
		http.MethodDelete, "/user/identities/12", `{"password":"secret"}`,
	))

	if malformed.Code != fromService.Code || malformed.Message != fromService.Message {
		t.Fatalf("malformed = %#v, service = %#v, want identical code and message", malformed, fromService)
	}
	if malformed.Message != "绑定记录不存在" {
		t.Fatalf("message = %q, want 绑定记录不存在", malformed.Message)
	}
}
