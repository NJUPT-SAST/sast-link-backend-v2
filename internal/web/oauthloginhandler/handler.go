// Package oauthloginhandler serves the third-party OAuth login, binding and
// login-code exchange endpoints.
package oauthloginhandler

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauthlogin"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/webutil"
)

// decodeStrictJSON is the shared strict body decoder, kept here under its
// historical lowercase name so the call sites in this package did not change.
var decodeStrictJSON = webutil.DecodeStrictJSON

// Service is the use-case surface this handler drives.
type Service interface {
	Authorize(ctx context.Context, input oauthlogin.AuthorizeInput) (*oauthlogin.AuthorizeResult, error)
	Callback(ctx context.Context, input oauthlogin.CallbackInput) (*oauthlogin.CallbackResult, error)
	ExchangeCode(ctx context.Context, input oauthlogin.ExchangeCodeInput) (*oauthlogin.ExchangeCodeResult, error)
	Bind(ctx context.Context, input oauthlogin.BindInput) (*oauthlogin.BindResult, error)
}

// Handler serves the third-party OAuth endpoints.
type Handler struct {
	Service Service
	// Clock is injected so tests can pin "now"; expires_in is computed against it
	// to stay consistent with the token exp the service signs.
	Clock auth.Clock
	// ErrorRedirect is the frontend page a failed callback is sent to. The
	// callback arrives in a browser, so answering with a JSON envelope would
	// show the user raw JSON; it redirects with an error query instead.
	ErrorRedirect string
	// Cookies writes the httpOnly session cookie on exchange-code success, so a
	// third-party login also establishes the browser-level session. Nil in tests
	// that don't exercise the cookie flow.
	Cookies *middleware.SessionCookie
	// StateCookie writes the login-CSRF state cookie at authorize time and reads
	// it back at callback time. Nil is not a valid production configuration: the
	// handler then never writes or reads a state cookie, and the service refuses
	// every third-party callback for a missing one — wiring it in runtime.go is
	// mandatory.
	StateCookie *middleware.SessionCookie
}

func (h Handler) now() time.Time {
	if h.Clock != nil {
		return h.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

// readStateCookie returns the login-CSRF state cookie value, or an empty string
// when the cookie is absent or the handler is not wired to write it.
func (h Handler) readStateCookie(c *gin.Context) string {
	if h.StateCookie == nil || strings.TrimSpace(h.StateCookie.Name) == "" {
		return ""
	}
	value, err := c.Cookie(h.StateCookie.Name)
	if err != nil {
		return ""
	}
	return value
}

// RegisterRoutes mounts the third-party OAuth endpoints.
//
// The authorize/callback legs and POST /oauth/exchange-code are unauthenticated:
// redeeming a login_code is how a session is obtained, so requiring one would be
// circular. The binding endpoints sit behind the JWT middleware because they
// attach a provider account to a known caller.
// Gates are the middleware the protected binding routes are mounted behind.
type Gates struct {
	// RequireAuth authenticates the group (the JWT middleware).
	RequireAuth gin.HandlerFunc
	// RequireWriteScope bounds what a scoped token may do on the binding routes;
	// it is a no-op for an internal console token.
	RequireWriteScope gin.HandlerFunc
}

// WriteScopes is the scope a delegated token must hold to attach a third-party
// login method to the subject's account, matching the email-bind routes.
var WriteScopes = []string{scope.UserWrite}

func RegisterRoutes(r gin.IRouter, h Handler, g Gates) {
	if g.RequireAuth == nil || g.RequireWriteScope == nil {
		panic("oauthloginhandler: every gate in Gates must be set")
	}
	r.GET("/oauth/github", h.authorize(model.LoginMethodGitHub))
	r.GET("/oauth/github/callback", h.callback(model.LoginMethodGitHub))
	r.GET("/oauth/lark", h.authorize(model.LoginMethodLark))
	r.GET("/oauth/lark/callback", h.callback(model.LoginMethodLark))
	r.POST("/oauth/exchange-code", h.ExchangeCode)

	// The binding routes name a write scope gate explicitly: a stolen token
	// carrying only a read scope (or none) cannot attach a new login method.
	protected := r.Group("")
	protected.Use(g.RequireAuth)
	protected.POST("/user/identities/github", g.RequireWriteScope, h.bind(model.LoginMethodGitHub))
	protected.POST("/user/identities/lark", g.RequireWriteScope, h.bind(model.LoginMethodLark))
}

// authorize returns the handler that starts a login for one provider.
//
// The provider is bound at registration time rather than read from the request,
// so no query parameter can retarget the flow.
func (h Handler) authorize(name model.LoginMethod) gin.HandlerFunc {
	return func(c *gin.Context) {
		result, err := h.Service.Authorize(c.Request.Context(), oauthlogin.AuthorizeInput{
			Provider:  name,
			Redirect:  c.Query("redirect"),
			ClientIP:  c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		})
		if err != nil {
			response.Error(c, mapServiceError(err))
			return
		}
		// The login-CSRF binding: the state digest cookie ties this callback to
		// the browser that started the authorization, so a state an attacker
		// started cannot complete here.
		if h.StateCookie != nil {
			h.StateCookie.Set(c, result.StateDigest, result.StateTTL)
		}
		// 302 rather than 307: this is a plain GET with no body to preserve, and
		// 302 is what every OAuth client expects here.
		c.Redirect(http.StatusFound, result.AuthorizeURL)
	}
}

// callback returns the handler for one provider's callback. Both outcomes are
// redirects, because the user is in a browser. A failure goes to ErrorRedirect
// carrying an error code the frontend can translate; it deliberately does not
// carry the provider's own error text, which can contain arbitrary content.
func (h Handler) callback(name model.LoginMethod) gin.HandlerFunc {
	return func(c *gin.Context) {
		result, err := h.Service.Callback(c.Request.Context(), oauthlogin.CallbackInput{
			Provider:      name,
			Code:          c.Query("code"),
			State:         c.Query("state"),
			ProviderError: c.Query("error"),
			ClientIP:      c.ClientIP(),
			UserAgent:     c.Request.UserAgent(),
			StateCookie:   h.readStateCookie(c),
		})
		if err != nil {
			// The state is consumed either way; the cookie pairing it is spent too.
			if h.StateCookie != nil {
				h.StateCookie.Clear(c)
			}
			h.redirectFailure(c, err)
			return
		}
		if h.StateCookie != nil {
			h.StateCookie.Clear(c)
		}

		target, parseErr := url.Parse(result.Redirect)
		if parseErr != nil || result.Redirect == "" {
			// The service only returns allow-listed redirects, so this is a configuration
			// fault rather than user input; answer in the envelope instead of redirecting
			// somewhere unvalidated.
			response.Error(c, &response.BusinessError{
				HTTPStatus: http.StatusInternalServerError,
				Code:       errcode.CodeInternal,
				Message:    "回调重定向地址无效",
			})
			return
		}

		query := target.Query()
		if result.Cancelled {
			// The user declined on the provider's page; the frontend reads
			// error=access_denied and renders its own "已取消登录" state.
			query.Set("error", "access_denied")
			query.Set("provider", result.Provider)
		} else if result.Bound {
			query.Set("code", result.LoginCode)
		} else {
			// The registration branch carries the parked state plus display
			// hints so the frontend can prefill the form. The identity itself
			// stays server-side in Redis.
			query.Set("registration_state", result.RegistrationState)
			// The OAuth state travels with it because POST /auth/register requires both
			// halves of the double binding, and the page that started the login was
			// unloaded by the redirect — the frontend has no other way to still hold it.
			// Emitting it does not defeat the pairing: a registration_state leaked on its
			// own is not redeemable, and an attacker who can read this redirect already
			// holds both values plus the session it belongs to.
			query.Set("oauth_state", result.OAuthState)
			query.Set("provider", result.Provider)
			if result.DisplayName != "" {
				query.Set("name", result.DisplayName)
			}
			if result.AvatarURL != "" {
				query.Set("avatar", result.AvatarURL)
			}
		}
		target.RawQuery = query.Encode()
		c.Redirect(http.StatusFound, target.String())
	}
}

// redirectFailure sends a failed callback to the frontend error page.
//
// When no error page is configured the envelope is used instead — worse UX but
// never worse security, since the alternative would be redirecting to an
// unvalidated location.
func (h Handler) redirectFailure(c *gin.Context, err error) {
	mapped := mapServiceError(err)
	if strings.TrimSpace(h.ErrorRedirect) == "" {
		response.Error(c, mapped)
		return
	}
	target, parseErr := url.Parse(h.ErrorRedirect)
	if parseErr != nil {
		response.Error(c, mapped)
		return
	}
	query := target.Query()
	var business *response.BusinessError
	if errors.As(mapped, &business) {
		query.Set("error", strconv.Itoa(business.Code))
		// The message is this service's own fixed string, not provider text, so it is
		// safe to pass through.
		query.Set("error_description", business.Message)
	} else {
		query.Set("error", strconv.Itoa(errcode.CodeInternal))
	}
	target.RawQuery = query.Encode()
	c.Redirect(http.StatusFound, target.String())
}

// exchangeCodeRequest redeems a login_code.
type exchangeCodeRequest struct {
	Code string `json:"code" binding:"required"`
}

// ExchangeCode swaps a one-time login_code for a session.
func (h Handler) ExchangeCode(c *gin.Context) {
	var request exchangeCodeRequest
	if err := decodeStrictJSON(c, &request); err != nil {
		response.Error(c, webutil.BadRequest())
		return
	}
	result, err := h.Service.ExchangeCode(c.Request.Context(), oauthlogin.ExchangeCodeInput{
		Code:      request.Code,
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	// Establish the browser-level session cookie (nil-safe: tests without cookie
	// config skip it; a zero or past expiry is a no-op inside SessionCookie.Set).
	h.Cookies.Set(c, result.RefreshToken, result.RefreshExpiresAt.Sub(h.now()))
	response.Ok(c, authResultDTO{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    result.TokenType,
		ExpiresIn:    expiresIn(h.now(), result.AccessExpiresAt),
		User:         mapUser(result.User),
	})
}

// bind returns the handler that attaches one provider account to the caller.
//
// The code arrives as a query parameter, matching the documented contract. For a
// provider that supports multiple callbacks (Lark), redirect_uri must be echoed
// back when exchanging the code, so the caller passes the exact callback the
// code was issued against.
// bindPasswordRequest carries the step-up password. The code and redirect_uri
// arrive as query parameters (mirroring the documented contract), while the body
// holds only the re-authentication credential.
type bindPasswordRequest struct {
	Password string `json:"password" binding:"required"`
}

func (h Handler) bind(name model.LoginMethod) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := middleware.PrincipalFrom(c)
		if !ok {
			response.Error(c, &response.BusinessError{
				HTTPStatus: http.StatusUnauthorized,
				Code:       errcode.CodeUnauthenticated,
				Message:    "未登录",
			})
			return
		}
		var body bindPasswordRequest
		if err := decodeStrictJSON(c, &body); err != nil {
			response.Error(c, webutil.BadRequest())
			return
		}
		result, err := h.Service.Bind(c.Request.Context(), oauthlogin.BindInput{
			UserID:      principal.UserID,
			Provider:    name,
			Code:        c.Query("code"),
			RedirectURI: c.Query("redirect_uri"),
			Password:    body.Password,
			ClientIP:    c.ClientIP(),
			UserAgent:   c.Request.UserAgent(),
		})
		if err != nil {
			response.Error(c, mapServiceError(err))
			return
		}
		response.Ok(c, identityBindDTO{
			Message:  bindMessage(name),
			Identity: mapIdentity(result.Identity),
		})
	}
}

// bindMessage is the per-provider success text the contract documents.
func bindMessage(name model.LoginMethod) string {
	if name == model.LoginMethodLark {
		return "飞书账号绑定成功"
	}
	return "GitHub 账号绑定成功"
}

// expiresIn converts an absolute expiry to the contract's relative seconds,
// measured from the injected clock so it agrees with the token's exp. A past
// instant yields 0 rather than a negative number.
func expiresIn(now, expiresAt time.Time) int {
	// Ceil so a near-expiry token reports the same TTL as the OAuth token endpoint.
	seconds := int(math.Ceil(expiresAt.Sub(now).Seconds()))
	if seconds < 0 {
		return 0
	}
	return seconds
}
