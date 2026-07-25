package response

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
)

func TestOk(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Ok(c, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestErrorBusiness(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Error(c, &BusinessError{
		HTTPStatus: http.StatusBadRequest,
		Code:       errcode.CodeBadRequest,
		Message:    "bad request",
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestErrorRetryAfterRoundsUp(t *testing.T) {
	tests := []struct {
		name       string
		retryAfter time.Duration
		want       string
	}{
		{name: "negative", retryAfter: -time.Second},
		{name: "zero"},
		{name: "nanosecond", retryAfter: time.Nanosecond, want: "1"},
		{name: "subsecond", retryAfter: 999 * time.Millisecond, want: "1"},
		{name: "exact second", retryAfter: time.Second, want: "1"},
		{name: "fractional second", retryAfter: 1001 * time.Millisecond, want: "2"},
		{name: "exact multiple", retryAfter: 2 * time.Second, want: "2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			Error(c, &BusinessError{
				HTTPStatus: http.StatusTooManyRequests,
				Code:       errcode.CodeRateLimited,
				Message:    "rate limited",
				RetryAfter: test.retryAfter,
			})

			if got := w.Header().Get("Retry-After"); got != test.want {
				t.Fatalf("Retry-After = %q, want %q", got, test.want)
			}
		})
	}
}

func TestErrorUnknown(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Error(c, errors.New("boom"))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestErrorWrappedBusiness(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	inner := &BusinessError{
		HTTPStatus: http.StatusUnauthorized,
		Code:       errcode.CodeUnauthenticated,
		Message:    "unauthorized",
	}
	Error(c, fmt.Errorf("handler failed: %w", inner))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
