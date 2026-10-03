package departmenthandler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestListDepartments(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/departments", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var body struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Departments []struct {
				Key   string `json:"key"`
				Label string `json:"label"`
			} `json:"departments"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Code != 0 || body.Message != "ok" {
		t.Fatalf("envelope = {code:%d, message:%q}, want {0, \"ok\"}", body.Code, body.Message)
	}
	if len(body.Data.Departments) != 7 {
		t.Fatalf("departments length = %d, want 7", len(body.Data.Departments))
	}
	first := body.Data.Departments[0]
	if first.Key != "software" || first.Label != "软件研发部" {
		t.Fatalf("first entry = {%s %s}, want {software 软件研发部}", first.Key, first.Label)
	}
	last := body.Data.Departments[len(body.Data.Departments)-1]
	if last.Key != "competition" || last.Label != "赛事部" {
		t.Fatalf("last entry = {%s %s}, want {competition 赛事部}", last.Key, last.Label)
	}
}
