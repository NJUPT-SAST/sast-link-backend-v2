package oauthhandler

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauth"
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
}

// Handler serves the OAuth 2.1 and OIDC endpoints.
type Handler struct {
	Service Service
	// Auth backs /userinfo, which authenticates itself rather than sitting behind
	// the JWT middleware so it can answer in RFC 6750 form.
	Auth Authenticator
	// ConsentURL is the front-end page that collects the user's decision.
	ConsentURL string
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
	c.Redirect(http.StatusFound, h.consentPageURL(map[string]string{
		"request_id":  result.RequestID,
		"client_name": result.ClientName,
		"scope":       strings.Join(result.Scopes, " "),
		// The stash lifetime, so the page can show the deadline instead of
		// submitting into a 400 with no warning.
		"expires_in": strconv.Itoa(result.ExpiresIn),
	}))
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
