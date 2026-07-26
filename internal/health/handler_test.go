package health

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHealthAllOk(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	h := New(map[string]func() error{
		"db":    func() error { return nil },
		"redis": func() error { return nil },
	})
	h.Handle(c)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHealthDBDown(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	h := New(map[string]func() error{
		"db":    func() error { return errors.New("connection refused") },
		"redis": func() error { return nil },
	})
	h.Handle(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	var body healthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body.Status != statusError || body.DB != statusError {
		t.Errorf("body = %#v, want status and db %q", body, statusError)
	}
}

// Redis is optional: the instance stays healthy so orchestrators do not restart
// a container that is still able to serve authenticated traffic from the DB.
func TestHealthRedisDownStaysHealthyAndReportsDegraded(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	h := New(map[string]func() error{
		"db":    func() error { return nil },
		"redis": func() error { return errors.New("connection refused") },
	})
	h.Handle(c)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var body healthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body.Status != statusOK || body.DB != statusOK || body.Redis != statusDegraded {
		t.Errorf("body = %#v, want status/db ok and redis %q", body, statusDegraded)
	}
}

func TestHealthBothDownReportsError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	h := New(map[string]func() error{
		"db":    func() error { return errors.New("connection refused") },
		"redis": func() error { return errors.New("connection refused") },
	})
	h.Handle(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	var body healthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body.Status != statusError || body.Redis != statusDegraded {
		t.Errorf("body = %#v, want status error and redis degraded", body)
	}
}
