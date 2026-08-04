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

func TestListDevicesReturnsArray(t *testing.T) {
	gin.SetMode(gin.TestMode)
	login := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	seen := login.Add(time.Hour)
	service := &fakeService{listDevicesResult: &session.ListDevicesResult{
		Devices: []session.DeviceRecord{
			{DeviceID: "family-new", UA: "browser/5", IP: "10.0.0.1", LoginTime: login, LastSeen: seen},
			{DeviceID: "family-old", UA: "app/2", IP: "10.0.0.2", LoginTime: login.Add(-time.Hour), LastSeen: login},
		},
	}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodGet, "/user/devices", "")

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	devices := body.Data.(map[string]any)["devices"].([]any)
	if len(devices) != 2 {
		t.Fatalf("devices = %#v, want 2", devices)
	}
	first := devices[0].(map[string]any)
	if first["device_id"] != "family-new" || first["ua"] != "browser/5" || first["ip"] != "10.0.0.1" {
		t.Fatalf("first device = %#v", first)
	}
	if first["login_time"] != "2026-07-22T10:00:00Z" || first["last_seen"] != "2026-07-22T11:00:00Z" {
		t.Fatalf("first device times = %#v", first)
	}
	if service.listDevicesInput.UserID != 42 {
		t.Fatalf("user id = %d, want 42", service.listDevicesInput.UserID)
	}
}

// An empty device list must serialize as [] rather than null, so clients can
// iterate the field unconditionally.
func TestListDevicesRendersEmptyArray(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{listDevicesResult: &session.ListDevicesResult{}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodGet, "/user/devices", "")

	raw := recorder.Body.String()
	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	if !strings.Contains(raw, `"devices":[]`) {
		t.Fatalf("body = %s, want empty array", raw)
	}
}

func TestLogoutDeviceCallsServiceAndReplies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{logoutDeviceResult: &session.LogoutDeviceResult{DeviceID: "family-123"}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodDelete, "/user/devices/family-123", "")

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	if service.logoutDeviceInput.UserID != 42 || service.logoutDeviceInput.DeviceID != "family-123" {
		t.Fatalf("input = %+v, want user 42 device family-123", service.logoutDeviceInput)
	}
	if service.logoutDeviceCalls != 1 {
		t.Fatalf("calls = %d, want 1", service.logoutDeviceCalls)
	}
}

func TestLogoutDeviceMapsServiceErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// The service raises a wrapped error carrying the device-specific message
	// (newError(ErrDeviceNotFound, "设备不存在", nil)); the sentinel alone has
	// no message, so the fake must mirror the real path.
	service := &fakeService{logoutDeviceErr: &session.Error{Kind: session.KindNotFound, Code: errcode.CodeNotFound, Message: "设备不存在"}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodDelete, "/user/devices/nope", "")

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusNotFound || body.Code != 40400 {
		t.Fatalf("response = %d %#v, want 404 40400", recorder.Code, body)
	}
	if body.Message != "设备不存在" {
		t.Fatalf("message = %q, want the device-specific message (not the unbind one)", body.Message)
	}
}

func TestLogoutDeviceEmptyPathIsNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodDelete, "/user/devices/", "")

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("response = %d, want 404 for an empty device id", recorder.Code)
	}
	if service.logoutDeviceCalls != 0 {
		t.Fatal("empty device id must not reach the service")
	}
}
