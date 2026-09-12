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

// A mistyped tri-state filter must be an error rather than a silent false: on
// needs_completion, reading "ture" as false would return exactly the accounts the
// caller asked to exclude, and the response would look like it worked.
func TestParseOptionalBoolRejectsUnrecognizedValues(t *testing.T) {
	for _, raw := range []string{"ture", "1", "t", "T", "F", "yes", "TRUE"} {
		if _, err := ParseOptionalBool(raw); !errors.Is(err, ErrInvalidQueryParameter) {
			t.Errorf("ParseOptionalBool(%q) error = %v, want ErrInvalidQueryParameter", raw, err)
		}
	}
}

func TestParseOptionalBoolReadsTriState(t *testing.T) {
	absent, err := ParseOptionalBool("")
	if err != nil || absent != nil {
		t.Fatalf("ParseOptionalBool(\"\") = %v, %v, want nil, nil so an absent filter stays unset", absent, err)
	}
	// Surrounding whitespace is a transport artifact, not a different value.
	trueValue, err := ParseOptionalBool(" true ")
	if err != nil || trueValue == nil || !*trueValue {
		t.Fatalf("ParseOptionalBool(\" true \") = %v, %v, want true", trueValue, err)
	}
	falseValue, err := ParseOptionalBool("false")
	if err != nil || falseValue == nil || *falseValue {
		t.Fatalf("ParseOptionalBool(\"false\") = %v, %v, want false", falseValue, err)
	}
}
