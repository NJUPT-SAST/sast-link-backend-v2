package sessionhandler

import (
	"bytes"
	"context"
	"image"
	"image/png"
	"mime/multipart"
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

// avatarMultipartRequest builds a PUT /user/avatar body with one file part.
func avatarMultipartRequest(t *testing.T, content []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "avatar.png")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write form part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/user/avatar", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func testPNGBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 4, 4))); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

func TestUploadAvatarHandlerSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{uploadAvatarResult: &session.UploadAvatarResult{
		AvatarURL: "https://cdn.example.com/avatar/42/abc.png",
	}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service, Clock: fixedClock{value: time.Now()}}, allowAuthWith(middleware.Principal{UserID: 42, JTI: "jti", ExpiresAt: time.Now().Add(time.Hour)}))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, avatarMultipartRequest(t, testPNGBytes(t)))

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 || body.Message != "ok" {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	data := body.Data.(map[string]any)
	if data["avatar_url"] != "https://cdn.example.com/avatar/42/abc.png" {
		t.Fatalf("avatar_url = %v", data["avatar_url"])
	}
	if service.uploadAvatarCalls != 1 {
		t.Fatalf("upload calls = %d, want 1", service.uploadAvatarCalls)
	}
	if service.uploadAvatarInput.UserID != 42 {
		t.Fatalf("input user id = %d, want 42", service.uploadAvatarInput.UserID)
	}
	if service.uploadAvatarInput.Size != int64(len(testPNGBytes(t))) {
		t.Fatalf("input size = %d, want %d", service.uploadAvatarInput.Size, len(testPNGBytes(t)))
	}
	if service.uploadAvatarInput.Content == nil {
		t.Fatal("input content is nil, want the file stream")
	}
}

// A missing file part is a client error answered with the generic 40000.
func TestUploadAvatarHandlerMissingFile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service, Clock: fixedClock{value: time.Now()}}, allowAuth())

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/user/avatar",
		strings.NewReader("--boundary-no-file"))
	request.Header.Set("Content-Type", "multipart/form-data; boundary=boundary-no-file")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusBadRequest || body.Code != errcode.CodeBadRequest {
		t.Fatalf("response = %d %#v, want 40000", recorder.Code, body)
	}
	if service.uploadAvatarCalls != 0 {
		t.Fatalf("upload calls = %d, want 0 (rejected before service)", service.uploadAvatarCalls)
	}
}

// Service errors are mapped through the shared mapper like every other endpoint.
func TestUploadAvatarHandlerMapsServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{uploadAvatarErr: &session.Error{Kind: session.KindObjectUploadFailed, Code: errcode.CodeObjectUploadFailed, Message: "头像上传失败"}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service, Clock: fixedClock{value: time.Now()}}, allowAuth())
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, avatarMultipartRequest(t, testPNGBytes(t)))

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusInternalServerError || body.Code != errcode.CodeObjectUploadFailed {
		t.Fatalf("response = %d %#v, want 50002", recorder.Code, body)
	}
}
