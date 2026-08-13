package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// SessionCookie manages the httpOnly session cookie that lets a fresh tab
// recognise an already-signed-in browser. The cookie value is the rotating
// refresh token, so /auth/refresh treats it as the refresh credential when the
// JSON body carries none.
//
// Attributes follow the production topology: frontend and backend are same
// origin on link.sast.fun (frontend at /, API under /v2 via the Caddy proxy),
// so the cookie is host-only, scoped to /v2, and SameSite=Lax — cross-site
// POSTs never carry it, which blocks cookie-CSRF on the refresh endpoint while
// still letting same-site navigations and top-level GETs through.
type SessionCookie struct {
	Name     string
	Path     string
	Secure   bool
	SameSite http.SameSite
}

// Set writes the session cookie for a refresh token's remaining lifetime. It is
// a no-op on a nil receiver (handlers without cookie config), so call sites do
// not need their own nil guard.
func (s *SessionCookie) Set(c *gin.Context, value string, maxAge time.Duration) {
	if s == nil {
		return
	}
	// Below one second the cookie is not worth writing: Go omits Max-Age for a
	// zero value and a sub-second truncation would land on that ambiguous spot
	// (an ephemeral session cookie), while a negative Max-Age serializes as a
	// delete. An expired or near-expired token gets a no-op instead of a silent
	// clear or a near-dead cookie on a success path.
	if maxAge < time.Second {
		return
	}
	// #nosec G124 -- Secure/HttpOnly/SameSite are set here and their values come
	// from config (SessionCookie fields); gosec cannot trace the struct fields.
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     s.Name,
		Value:    value,
		Path:     s.Path,
		MaxAge:   int(maxAge / time.Second),
		Secure:   s.Secure,
		HttpOnly: true,
		SameSite: s.SameSite,
	})
}

// Clear deletes the session cookie (logout, password change). No-op on nil.
func (s *SessionCookie) Clear(c *gin.Context) {
	if s == nil {
		return
	}
	// #nosec G124 -- see Set.
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     s.Name,
		Value:    "",
		Path:     s.Path,
		MaxAge:   -1,
		Secure:   s.Secure,
		HttpOnly: true,
		SameSite: s.SameSite,
	})
}

// Read returns the session cookie value, or "" when unset or nil.
func (s *SessionCookie) Read(c *gin.Context) string {
	if s == nil {
		return ""
	}
	if cookie, err := c.Cookie(s.Name); err == nil {
		return cookie
	}
	return ""
}
