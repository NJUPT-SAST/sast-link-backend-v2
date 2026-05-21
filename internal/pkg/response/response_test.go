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

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if !resp.Success {
		t.Error("Success = false, want true")
	}
	if resp.ErrCode != 200 {
		t.Errorf("ErrCode = %d, want 200", resp.ErrCode)
	}
	if resp.ErrMsg != "" {
		t.Errorf("ErrMsg = %q, want empty", resp.ErrMsg)
	}
}

func TestErr(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Err(c, domain.ErrInvalidParams, "bad request")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Success {
		t.Error("Success = true, want false")
	}
	if resp.ErrCode != 10001 {
		t.Errorf("ErrCode = %d, want 10001", resp.ErrCode)
	}
	if resp.ErrMsg != "bad request" {
		t.Errorf("ErrMsg = %q, want bad request", resp.ErrMsg)
	}
	if resp.Data != nil {
		t.Error("Data should be nil for error response")
	}
}

func TestErrWithStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	ErrWithStatus(c, http.StatusNotFound, domain.ErrInternal, "not found")

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Success {
		t.Error("Success = true, want false")
	}
	if resp.ErrCode != 50000 {
		t.Errorf("ErrCode = %d, want 50000", resp.ErrCode)
	}
	if resp.ErrMsg != "not found" {
		t.Errorf("ErrMsg = %q, want not found", resp.ErrMsg)
	}
}
