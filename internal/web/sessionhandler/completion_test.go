package sessionhandler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
)

// The completion prompt is only reachable if the flag rides along on the login
// response itself. A client that had to call GET /user/profile to discover it
// would either delay the redirect by a round trip or skip the check entirely.
func TestLoginCarriesProfileCompletionFlag(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	service := &fakeService{loginResult: &session.LoginResult{
		AccessToken:     "access",
		RefreshToken:    "refresh",
		TokenType:       "Bearer",
		AccessExpiresAt: now.Add(90 * time.Second),
		Profile: session.UserProfileDTO{
			ID:                     42,
			Name:                   "B24040525",
			LoginEmail:             "b24040525@njupt.edu.cn",
			Role:                   "freshman",
			State:                  "njupter",
			StudentID:              "B24040525",
			ProfileNeedsCompletion: true,
			IncompleteFields:       []string{"name", "phone_number", "major"},
		},
	}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service, Clock: fixedClock{value: now}}, scopedGates(allowAuth()))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/user/login",
		strings.NewReader(`{"login_email":"b24040525@njupt.edu.cn","password":"secret"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %#v", recorder.Code, body)
	}
	user := body.Data.(map[string]any)["user"].(map[string]any)
	if user["profile_needs_completion"] != true {
		t.Fatalf("profile_needs_completion = %#v, want true", user["profile_needs_completion"])
	}
	fields, ok := user["incomplete_fields"].([]any)
	if !ok {
		t.Fatalf("incomplete_fields = %#v, want an array", user["incomplete_fields"])
	}
	if len(fields) != 3 || fields[0] != "name" || fields[1] != "phone_number" || fields[2] != "major" {
		t.Fatalf("incomplete_fields = %#v", fields)
	}
}

// A healthy account must report an empty array rather than null, so a client can
// read .length without a nil guard. This is the common case, so getting it wrong
// would break every request rather than only the backlog's.
func TestLoginReportsEmptyArrayForCompleteProfile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	service := &fakeService{loginResult: &session.LoginResult{
		AccessToken:     "access",
		RefreshToken:    "refresh",
		TokenType:       "Bearer",
		AccessExpiresAt: now.Add(90 * time.Second),
		Profile: session.UserProfileDTO{
			ID: 7, Name: "张三", LoginEmail: "pt@sast.fun", Role: "member", State: "on_sast",
			ProfileNeedsCompletion: false,
			IncompleteFields:       nil,
		},
	}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service, Clock: fixedClock{value: now}}, scopedGates(allowAuth()))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/user/login",
		strings.NewReader(`{"login_email":"pt@sast.fun","password":"secret"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	user := decodeBody(t, recorder).Data.(map[string]any)["user"].(map[string]any)
	if user["profile_needs_completion"] != false {
		t.Fatalf("profile_needs_completion = %#v, want false", user["profile_needs_completion"])
	}
	fields, ok := user["incomplete_fields"].([]any)
	if !ok {
		t.Fatalf("incomplete_fields = %#v, want [] rather than null", user["incomplete_fields"])
	}
	if len(fields) != 0 {
		t.Fatalf("incomplete_fields = %#v, want empty", fields)
	}
}

// The completion page itself reads GET /user/profile, so the same two fields have
// to appear there as well.
func TestProfileCarriesCompletionFlag(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{profileResult: &session.ProfileResult{
		Profile: session.UserProfileDTO{
			ID: 42, Name: "李四", LoginEmail: "b24040002@njupt.edu.cn",
			Role: "freshman", State: "njupter", StudentID: "B24040002",
			ProfileNeedsCompletion: true,
			IncompleteFields:       []string{"phone_number", "major"},
		},
	}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, scopedGates(allowAuth()))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/user/profile", nil)
	router.ServeHTTP(recorder, request)

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %#v", recorder.Code, body)
	}
	data := body.Data.(map[string]any)
	if data["profile_needs_completion"] != true {
		t.Fatalf("profile_needs_completion = %#v, want true", data["profile_needs_completion"])
	}
	fields := data["incomplete_fields"].([]any)
	if len(fields) != 2 || fields[0] != "phone_number" || fields[1] != "major" {
		t.Fatalf("incomplete_fields = %#v", fields)
	}
}
