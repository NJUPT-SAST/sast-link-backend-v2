package badgehandler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/badge"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
)

type fakeService struct {
	enableResult *badge.Status
	enableErr    error
	disableErr   error
	statusResult *badge.Status
	statusErr    error
	enableInput  badge.EnableInput
	disableInput badge.DisableInput
	statusUserID int64
}

func (s *fakeService) Enable(_ context.Context, input badge.EnableInput) (*badge.Status, error) {
	s.enableInput = input
	return s.enableResult, s.enableErr
}

func (s *fakeService) Disable(_ context.Context, input badge.DisableInput) error {
	s.disableInput = input
	return s.disableErr
}

func (s *fakeService) Status(_ context.Context, userID int64) (*badge.Status, error) {
	s.statusUserID = userID
	return s.statusResult, s.statusErr
}

// newTestRouter mounts the handler with a middleware that injects a principal,
// so the authenticated management routes are reachable.
func newTestRouter(h Handler, userID int64) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	authMiddleware := func(c *gin.Context) {
		if userID > 0 {
			middleware.SetPrincipal(c, middleware.Principal{UserID: userID, ClientID: "sast-link-web"})
		}
		c.Next()
	}
	RegisterRoutes(router, h, Gates{
		RequireAuth:       authMiddleware,
		RequireReadScope:  func(c *gin.Context) { c.Next() },
		RequireWriteScope: func(c *gin.Context) { c.Next() },
	})
	return router
}

func decodeEnvelope(t *testing.T, body string) (int, string, map[string]any) {
	t.Helper()
	var envelope struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("decode envelope %q: %v", body, err)
	}
	return envelope.Code, envelope.Message, envelope.Data
}

func TestStatusReturnsSharingState(t *testing.T) {
	enabledAt := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	service := &fakeService{statusResult: &badge.Status{Enabled: true, Key: "k43chars", EnabledAt: enabledAt}}
	router := newTestRouter(Handler{Service: service}, 7)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/user/badge", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if service.statusUserID != 7 {
		t.Fatalf("Status called with user %d, want 7", service.statusUserID)
	}
	code, _, data := decodeEnvelope(t, recorder.Body.String())
	if code != 0 || data["enabled"] != true || data["key"] != "k43chars" {
		t.Fatalf("envelope = code %d data %v, want enabled with key", code, data)
	}
}

func TestStatusDisabledOmitsKey(t *testing.T) {
	service := &fakeService{statusResult: &badge.Status{Enabled: false}}
	router := newTestRouter(Handler{Service: service}, 7)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/user/badge", nil))

	_, _, data := decodeEnvelope(t, recorder.Body.String())
	if data["enabled"] != false {
		t.Fatalf("data = %v, want enabled=false", data)
	}
	if _, hasKey := data["key"]; hasKey {
		t.Fatalf("disabled status must omit the key, got %v", data)
	}
}

func TestEnableReturnsCreatedWithKey(t *testing.T) {
	service := &fakeService{enableResult: &badge.Status{Enabled: true, Key: "k43chars"}}
	router := newTestRouter(Handler{Service: service}, 7)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/user/badge", nil))

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", recorder.Code)
	}
	if service.enableInput.UserID != 7 || service.enableInput.ActorClientID != "sast-link-web" {
		t.Fatalf("Enable input = %#v, want user 7 with the principal's client", service.enableInput)
	}
	_, _, data := decodeEnvelope(t, recorder.Body.String())
	if data["key"] != "k43chars" {
		t.Fatalf("data = %v, want the badge key", data)
	}
}

func TestEnableMapsBusinessErrors(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantHTTP int
		wantCode int
	}{
		{
			name:     "nickname missing is 422 with user-facing copy",
			err:      badge.ErrNicknameMissing,
			wantHTTP: http.StatusUnprocessableEntity,
			wantCode: 42205,
		},
		{
			name:     "already enabled is 409",
			err:      badge.ErrAlreadyEnabled,
			wantHTTP: http.StatusConflict,
			wantCode: 40907,
		},
		{
			name:     "unknown user is 404",
			err:      badge.ErrUserNotFound,
			wantHTTP: http.StatusNotFound,
			wantCode: 40401,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			service := &fakeService{enableErr: testCase.err}
			router := newTestRouter(Handler{Service: service}, 7)

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/user/badge", nil))

			if recorder.Code != testCase.wantHTTP {
				t.Fatalf("status = %d, want %d", recorder.Code, testCase.wantHTTP)
			}
			code, _, _ := decodeEnvelope(t, recorder.Body.String())
			if code != testCase.wantCode {
				t.Fatalf("code = %d, want %d", code, testCase.wantCode)
			}
		})
	}
}

func TestEnableRateLimitedSetsRetryAfter(t *testing.T) {
	rateLimited := &badge.Error{Kind: badge.KindRateLimited, Code: 42900, RetryAfter: 90 * time.Second}
	service := &fakeService{enableErr: rateLimited}
	router := newTestRouter(Handler{Service: service}, 7)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/user/badge", nil))

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", recorder.Code)
	}
	if got := recorder.Header().Get("Retry-After"); got != "90" {
		t.Fatalf("Retry-After = %q, want 90", got)
	}
}

func TestDisableIsIdempotentSuccess(t *testing.T) {
	service := &fakeService{}
	router := newTestRouter(Handler{Service: service}, 7)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/user/badge", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if service.disableInput.UserID != 7 {
		t.Fatalf("Disable input = %#v, want user 7", service.disableInput)
	}
	_, message, _ := decodeEnvelope(t, recorder.Body.String())
	if message != "ok" {
		t.Fatalf("message = %q, want ok", message)
	}
}

func TestRoutesRejectMissingPrincipal(t *testing.T) {
	// userID 0 leaves the principal unset; the handlers must answer 500 rather
	// than proceed with a zero subject.
	service := &fakeService{statusResult: &badge.Status{Enabled: false}}
	router := newTestRouter(Handler{Service: service}, 0)

	for _, target := range []string{"/user/badge"} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil))
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("GET %s without principal = %d, want 500", target, recorder.Code)
		}
	}
}
