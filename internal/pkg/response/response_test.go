package response

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
)

func TestOK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	OK(c, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Code != 0 {
		t.Errorf("Code = %d, want 0", resp.Code)
	}
	if resp.Message != "ok" {
		t.Errorf("Message = %q, want ok", resp.Message)
	}
	if resp.Data == nil {
		t.Error("Data should not be nil for success response")
	}
}

func TestCreated(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Created(c, map[string]int{"id": 1})

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	var resp Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Code != 0 {
		t.Errorf("Code = %d, want 0", resp.Code)
	}
}

func TestErr(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Err(c, domain.ErrInvalidParams, "请求参数错误")

	// 400xx → HTTP 400
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Code != 40000 {
		t.Errorf("Code = %d, want 40000", resp.Code)
	}
	if resp.Message != "请求参数错误" {
		t.Errorf("Message = %q, want 请求参数错误", resp.Message)
	}
	if resp.Data != nil {
		t.Error("Data should be nil for error response")
	}
}

func TestErrWithStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	ErrWithStatus(c, http.StatusNotFound, domain.ErrResourceNotFound, "资源不存在")

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}

	var resp Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Code != 40400 {
		t.Errorf("Code = %d, want 40400", resp.Code)
	}
	if resp.Message != "资源不存在" {
		t.Errorf("Message = %q, want 资源不存在", resp.Message)
	}
	if resp.Data != nil {
		t.Error("Data should be nil for error response")
	}
}

func TestEnvelopeJSONTags(t *testing.T) {
	e := Envelope{Code: 0, Message: "ok", Data: map[string]int{"id": 1}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify snake_case JSON keys
	for _, key := range []string{"code", "message", "data"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing key %q in JSON output", key)
		}
	}
}

func TestMessageData(t *testing.T) {
	md := MessageData{Message: "操作成功"}
	b, err := json.Marshal(md)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if m["message"] != "操作成功" {
		t.Errorf("message = %v, want 操作成功", m["message"])
	}
}
