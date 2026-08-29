package webutil

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type samplePayload struct {
	Name string `json:"name"`
}

func ginCtx(body, contentType string) *gin.Context {
	gin.SetMode(gin.TestMode)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req
	return c
}

func TestDecodeStrictJSONRequiresJSONContentType(t *testing.T) {
	var dst samplePayload
	if err := DecodeStrictJSON(ginCtx(`{"name":"x"}`, ""), &dst); err == nil {
		t.Fatal("missing Content-Type must be rejected")
	}
	if err := DecodeStrictJSON(ginCtx(`{"name":"x"}`, "text/plain"), &dst); err == nil {
		t.Fatal("non-JSON Content-Type must be rejected")
	}
}

func TestDecodeStrictJSONRejectsUnknownFields(t *testing.T) {
	var dst samplePayload
	if err := DecodeStrictJSON(ginCtx(`{"name":"x","extra":1}`, "application/json"), &dst); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}

func TestDecodeStrictJSONRejectsTrailingValue(t *testing.T) {
	var dst samplePayload
	if err := DecodeStrictJSON(ginCtx(`{"name":"x"} {}`, "application/json"), &dst); !errors.Is(err, ErrTrailingJSONValue) {
		t.Fatalf("trailing value error = %v, want ErrTrailingJSONValue", err)
	}
}

func TestDecodeStrictJSONValidates(t *testing.T) {
	var dst samplePayload
	if err := DecodeStrictJSON(ginCtx(`{"name":"x"}`, "application/json"), &dst); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}
	if dst.Name != "x" {
		t.Fatalf("name = %q, want x", dst.Name)
	}
}

func TestDecodeStrictJSONWithLimitCapsBody(t *testing.T) {
	var dst map[string]any
	big := strings.Repeat("a", 16<<10)
	if err := DecodeStrictJSONWithLimit(ginCtx(`{"blob":"`+big+`"}`, "application/json"), &dst, 8<<10); err == nil {
		t.Fatal("body past the 8 KiB cap must be rejected")
	}
}

func TestDecodeStrictJSONBytesRejectsTrailing(t *testing.T) {
	var dst samplePayload
	if err := DecodeStrictJSONBytes([]byte(`{"name":"x"} trailing`), &dst); !errors.Is(err, ErrTrailingJSONValue) {
		t.Fatalf("trailing junk error = %v, want ErrTrailingJSONValue", err)
	}
}
