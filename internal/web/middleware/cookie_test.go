package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestSessionCookieSetReadClear(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cookies := SessionCookie{
		Name:     "sl_session",
		Path:     "/v2",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	// Set writes the cookie with the production-required attributes.
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	cookies.Set(ctx, "refresh-token", time.Hour)
	setCookie := recorder.Header().Get("Set-Cookie")
	for _, want := range []string{
		"sl_session=refresh-token",
		"Path=/v2",
		"HttpOnly",
		"Secure",
		"SameSite=Lax",
	} {
		if !strings.Contains(setCookie, want) {
			t.Fatalf("Set-Cookie = %q, missing %q", setCookie, want)
		}
	}

	// Read returns the value carried in the request's Cookie header.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v2/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "sl_session", Value: "refresh-token", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	ctx.Request = req
	if got := cookies.Read(ctx); got != "refresh-token" {
		t.Fatalf("Read = %q, want refresh-token", got)
	}

	// Clear expires the cookie.
	clearRecorder := httptest.NewRecorder()
	clearCtx, _ := gin.CreateTestContext(clearRecorder)
	cookies.Clear(clearCtx)
	if got := clearRecorder.Header().Get("Set-Cookie"); !strings.Contains(got, "Max-Age=0") {
		t.Fatalf("Clear Set-Cookie = %q, want Max-Age=0", got)
	}
}

func TestSessionCookieSetNoopForSubSecondMaxAge(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cookies := SessionCookie{Name: "sl_session", Path: "/v2", SameSite: http.SameSiteLaxMode}

	// A zero or negative maxAge would serialize as Max-Age=0 (delete), and a
	// sub-second positive maxAge would truncate to an omitted Max-Age (an
	// ephemeral session cookie) — neither is worth writing on a success path
	// (e.g. a token whose expiry is already past under the service clock). Set
	// is a no-op below one second.
	for _, maxAge := range []time.Duration{0, -time.Hour, 500 * time.Millisecond} {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		cookies.Set(ctx, "value", maxAge)
		if got := recorder.Header().Get("Set-Cookie"); got != "" {
			t.Fatalf("Set with maxAge=%v wrote Set-Cookie %q, want no-op", maxAge, got)
		}
	}
}
