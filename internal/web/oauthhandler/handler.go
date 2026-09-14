package oauthhandler

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/webutil"
)

// maxOAuthBodyBytes caps the already-authenticated consent/grants request
// bodies at their historical 8 KiB: the shared 64 KiB default is generous, and
// a bounded-work surface must not absorb the extra headroom for nothing.
const maxOAuthBodyBytes int64 = 8 << 10

// Service is the OAuth use-case surface this handler drives.
type Service interface {
	Authorize(ctx context.Context, input oauth.AuthorizeInput) (*oauth.AuthorizeResult, error)
	Consent(ctx context.Context, input oauth.ConsentInput) (*oauth.ConsentResult, error)
	// SilentConsent completes a pending authorization from an identified link
	// session when the user's standing grant already covers the scopes.
	SilentConsent(ctx context.Context, input oauth.SilentConsentInput) (*oauth.ConsentResult, error)
	ConsentInfo(ctx context.Context, input oauth.ConsentInfoInput) (*oauth.ConsentInfoResult, error)
	Token(ctx context.Context, input oauth.TokenInput) (*oauth.TokenResult, error)
	Revoke(ctx context.Context, input oauth.RevokeInput) error
	UserInfo(ctx context.Context, input oauth.UserInfoInput) (*oauth.UserInfoResult, error)
	Discovery() map[string]any
	JWKS() map[string]any
	// Grants lists the applications a user has authorized; RevokeGrant removes
	// one application's access (every token with that client is revoked).
	Grants(ctx context.Context, userID int64) ([]repository.OAuthGrant, error)
	RevokeGrant(ctx context.Context, userID, clientID int64, actorClientID string) error
}

// Authenticator validates bearer tokens for the OAuth-facing endpoints.
//
// UserInfo deliberately uses the any-client variant: it exists to serve the
// third-party tokens this provider issues. Internal endpoints must use
// middleware.Authenticate instead, which rejects third-party tokens.
type Authenticator interface {
	AuthenticateAnyClient(ctx context.Context, header string) (middleware.Principal, error)
	// Authenticate admits only the internal client's session tokens. It backs the
	// silent authorize path, where a third-party application's own token must not
	// be able to vouch for the browser's link session.
	Authenticate(ctx context.Context, header string) (middleware.Principal, error)
}

// SessionRefresher renews a link session from its refresh credential. Refresh
// rotates the family exactly like POST /auth/refresh, so the silent authorize
// path admits precisely the sessions a fresh tab could rebuild.
type SessionRefresher interface {
	Refresh(ctx context.Context, input session.RefreshInput) (*session.RefreshResult, error)
}

// Handler serves the OAuth 2.1 and OIDC endpoints.
type Handler struct {
	Service Service
	// Auth backs /userinfo, which authenticates itself rather than sitting behind
	// the JWT middleware so it can answer in RFC 6750 form.
	Auth Authenticator
	// Sessions and Cookies back the silent authorize path's cookie leg: a
	// top-level navigation carries no Authorization header, only the httpOnly
	// session cookie, whose refresh token is rotated and written back here.
	Sessions SessionRefresher
	Cookies  *middleware.SessionCookie
	// ConsentURL is the front-end page that collects the user's decision.
	ConsentURL string
	// Clock is injected so tests can pin "now"; the session cookie's Max-Age is
	// computed against it to stay consistent with the rotated token's expiry.
	Clock auth.Clock
}

func (h Handler) now() time.Time {
	if h.Clock != nil {
		return h.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

// RegisterRoutes mounts the OAuth and OIDC endpoints.
//
// Only the consent endpoint sits behind the JWT middleware: GET /oauth/authorize
// is unauthenticated by design, and /userinfo authenticates itself because its
// error format is RFC 6750 rather than the standard envelope.
func RegisterRoutes(r gin.IRouter, h Handler, authMiddleware gin.HandlerFunc) {
	r.GET("/oauth/authorize", h.Authorize)
	r.POST("/oauth/token", h.Token)
	r.POST("/oauth/revoke", h.Revoke)
	r.GET("/.well-known/openid-configuration", h.Discovery)
	r.GET("/.well-known/jwks.json", h.JWKS)
	// OIDC permits both verbs on UserInfo; a GET keeps the token in the header
	// where it belongs, and a POST exists for clients that prefer it.
	r.GET("/userinfo", h.UserInfo)
	r.POST("/userinfo", h.UserInfo)

	consent := r.Group("")
	consent.Use(authMiddleware)
	consent.GET("/oauth/authorize/consent", h.ConsentInfo)
	consent.POST("/oauth/authorize/consent", h.Consent)
	consent.GET("/oauth/grants", h.Grants)
	consent.DELETE("/oauth/grants/:client_id", h.RevokeGrant)
}

// Authorize validates an authorization request and redirects to the consent page.
//
// Errors take one of two routes. A request whose client_id or redirect_uri could
// not be verified is sent to the consent page rather than redirected to the
// client — that would make this an open redirector. Once those are verified, the
// error is delivered to the client per RFC 6749 §4.1.2.1.
func (h Handler) Authorize(c *gin.Context) {
	input := oauth.AuthorizeInput{
		ResponseType:        c.Query("response_type"),
		ClientID:            c.Query("client_id"),
		RedirectURI:         c.Query("redirect_uri"),
		Scope:               c.Query("scope"),
		State:               c.Query("state"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
		Nonce:               c.Query("nonce"),
		ClientIP:            c.ClientIP(),
		UserAgent:           c.Request.UserAgent(),
	}
	result, err := h.Service.Authorize(c.Request.Context(), input)
	if err != nil {
		h.redirectAuthorizeError(c, input, err)
		return
	}
	// SSO fast path: when the browser carries a link session whose grant with
	// this client already covers the requested scopes, the code is minted here
	// and the browser goes straight back to the client — the consent page only
	// renders for a first authorization, a broader scope set, or no session.
	if redirect := h.trySilentConsent(c, result.RequestID, input.ClientIP); redirect != "" {
		c.Redirect(http.StatusFound, redirect)
		return
	}
	c.Redirect(http.StatusFound, h.consentPageURL(map[string]string{
		"request_id":  result.RequestID,
		"client_name": result.ClientName,
		"scope":       strings.Join(result.Scopes, " "),
		// The stash lifetime, so the page can show the deadline instead of
		// submitting into a 400 with no warning.
		"expires_in": strconv.Itoa(result.ExpiresIn),
	}))
}

// trySilentConsent attempts to complete a stashed authorization without the
// consent page and returns the client redirect on success, or "" when the flow
// must fall back to the consent page. Every silent failure — no recognizable
// session, no covering grant, a spent or dead stash, a throttle — is a normal
// fallback rather than an error the user sees: the consent page re-runs the
// same checks interactively.
func (h Handler) trySilentConsent(c *gin.Context, requestID, clientIP string) string {
	userID, ok := h.identifyUser(c)
	if !ok {
		return ""
	}
	result, err := h.Service.SilentConsent(c.Request.Context(), oauth.SilentConsentInput{
		RequestID: requestID,
		UserID:    userID,
		ClientIP:  clientIP,
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil || result == nil {
		return ""
	}
	return result.RedirectURI
}

// identifyUser resolves the browser's link session to a user ID for the silent
// authorize path, without which that path is skipped entirely.
//
// A Bearer header is tried first and must be an internal-client session token
// (middleware.Authenticate): a third-party token belongs to the application
// holding it, not to the browser's link session. Otherwise the httpOnly session
// cookie is refreshed exactly like POST /auth/refresh — the only other way a
// signed-in browser proves itself on a top-level navigation — and the rotated
// refresh token is written back, or the next request would present a dead one.
// A failed refresh clears nothing here: the standard refresh endpoint owns that
// decision, so a cross-site stray or a grace-window race degrades to the consent
// page instead of destroying a live cookie.
func (h Handler) identifyUser(c *gin.Context) (int64, bool) {
	if h.Auth != nil {
		if principal, err := h.Auth.Authenticate(c.Request.Context(), c.GetHeader("Authorization")); err == nil && principal.UserID > 0 {
			return principal.UserID, true
		}
	}
	if h.Sessions == nil || h.Cookies == nil {
		return 0, false
	}
	token := h.Cookies.Read(c)
	if token == "" {
		return 0, false
	}
	result, err := h.Sessions.Refresh(c.Request.Context(), session.RefreshInput{
		RefreshToken: token,
		ClientIP:     c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})
	if err != nil || result == nil || result.UserID <= 0 {
		return 0, false
	}
	h.Cookies.Set(c, result.RefreshToken, result.RefreshExpiresAt.Sub(h.now()))
	return result.UserID, true
}

// Consent records the user's decision and redirects to the client.
//
// The response is the standard envelope rather than a 302: the caller is the
// consent page's own fetch, which must read the target URL and navigate itself.
func (h Handler) Consent(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	var req consentRequest
	if err := webutil.DecodeStrictJSONWithLimit(c, &req, maxOAuthBodyBytes); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Service.Consent(c.Request.Context(), oauth.ConsentInput{
		RequestID: req.RequestID,
		Approve:   *req.Approve,
		UserID:    principal.UserID,
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapConsentError(err))
		return
	}
	response.Ok(c, consentResponse{RedirectURI: result.RedirectURI})
}

// ConsentInfo serves the pending request's verified client metadata to the
// consent page. Protected: only an authenticated user can read a pending
// request's display info. The request_id comes from the URL (it is the opaque
// handle the page was redirected to); everything shown comes from the stash.
func (h Handler) ConsentInfo(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	result, err := h.Service.ConsentInfo(c.Request.Context(), oauth.ConsentInfoInput{
		RequestID: c.Query("request_id"),
		UserID:    principal.UserID,
	})
	if err != nil {
		response.Error(c, mapConsentError(err))
		return
	}
	response.Ok(c, consentInfoResponse{
		ClientName: result.ClientName,
		Scopes:     result.Scopes,
		ExpiresIn:  result.ExpiresIn,
	})
}

// Token issues or rotates tokens.
func (h Handler) Token(c *gin.Context) {
	form, err := decodeStrictForm(c)
	if err != nil {
		writeError(c, invalidRequest(formErrorDescription(err)))
		return
	}
	result, err := h.Service.Token(c.Request.Context(), oauth.TokenInput{
		GrantType:    form.Get("grant_type"),
		Code:         form.Get("code"),
		RedirectURI:  form.Get("redirect_uri"),
		ClientID:     form.Get("client_id"),
		ClientSecret: form.Get("client_secret"),
		CodeVerifier: form.Get("code_verifier"),
		RefreshToken: form.Get("refresh_token"),
		ClientIP:     c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})
	if err != nil {
		writeError(c, err)
		return
	}
	// RFC 6749 §5.1 requires these headers: a token response must never be cached,
	// or a shared cache could serve one client's tokens to another.
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, tokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    result.TokenType,
		ExpiresIn:    result.ExpiresIn,
		IDToken:      result.IDToken,
		Scope:        result.Scope,
	})
}

// Revoke revokes a token family, per RFC 7009.
func (h Handler) Revoke(c *gin.Context) {
	form, err := decodeStrictForm(c)
	if err != nil {
		writeError(c, invalidRequest(formErrorDescription(err)))
		return
	}
	if err := h.Service.Revoke(c.Request.Context(), oauth.RevokeInput{
		Token:         form.Get("token"),
		TokenTypeHint: form.Get("token_type_hint"),
		ClientID:      form.Get("client_id"),
		ClientSecret:  form.Get("client_secret"),
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	}); err != nil {
		writeError(c, err)
		return
	}
	// RFC 7009 §2.2: success is 200 with an empty body.
	c.Header("Cache-Control", "no-store")
	c.Status(http.StatusOK)
}

// UserInfo returns the OIDC claims a token's scopes permit. It authenticates
// inline rather than behind the JWT middleware so a rejected token produces an
// RFC 6750 challenge; the validation itself is the middleware's, so the two
// paths cannot drift.
func (h Handler) UserInfo(c *gin.Context) {
	if h.Auth == nil {
		writeBearerError(c, oauth.ErrInternal)
		return
	}
	principal, err := h.Auth.AuthenticateAnyClient(c.Request.Context(), c.GetHeader("Authorization"))
	if err != nil {
		// RFC 6750 has exactly one code for every rejected token, so the middleware
		// error's finer reason is deliberately collapsed here.
		writeBearerError(c, invalidToken("Access Token 无效或已过期"))
		return
	}
	result, err := h.Service.UserInfo(c.Request.Context(), oauth.UserInfoInput{
		UserID: principal.UserID,
		Scopes: principal.Scopes,
	})
	if err != nil {
		writeBearerError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, result)
}

// Discovery serves the OIDC Discovery document.
func (h Handler) Discovery(c *gin.Context) {
	c.JSON(http.StatusOK, h.Service.Discovery())
}

// JWKS serves the public key set.
func (h Handler) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, h.Service.JWKS())
}

// redirectAuthorizeError routes an authorize failure to the client or to the
// consent page, depending on whether the redirect_uri was verified.
func (h Handler) redirectAuthorizeError(c *gin.Context, input oauth.AuthorizeInput, err error) {
	code, description, redirectable := authorizeErrorParts(err)
	if redirectable {
		// Trimmed to match what the service compared against the registration:
		// validating strings.TrimSpace(redirect_uri) but redirecting to the raw
		// value would let " https://app.example.com/cb" pass the registry check and
		// then be read by url.Parse as a relative path on this API's own host.
		c.Redirect(http.StatusFound, appendQuery(strings.TrimSpace(input.RedirectURI), map[string]string{
			"error":             code,
			"error_description": description,
			"state":             input.State,
		}))
		return
	}
	c.Redirect(http.StatusFound, h.consentPageURL(map[string]string{
		"error":             code,
		"error_description": description,
	}))
}

// consentPageURL builds a URL on the configured consent page.
func (h Handler) consentPageURL(parameters map[string]string) string {
	return appendQuery(h.ConsentURL, parameters)
}

// appendQuery merges parameters into a URL's existing query string.
func appendQuery(rawURL string, parameters map[string]string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	query := parsed.Query()
	for key, value := range parameters {
		if value == "" {
			continue
		}
		query.Set(key, value)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
