// Package oauthhandler exposes the OAuth 2.1 and OIDC endpoints over HTTP.
//
// These endpoints deliberately do not use the project's standard
// {code, message, data} envelope. RFC 6749 §5.2, RFC 7009 and RFC 6750 §3 each
// prescribe their own wire format, and a relying party's OAuth library parses
// those formats, not ours.
package oauthhandler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauth"
)

// errorResponse is the RFC 6749 §5.2 error body, also used by RFC 7009 and, with
// a WWW-Authenticate header, by RFC 6750 §3.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeError renders a service error in RFC 6749 form.
//
// An unrecognized error becomes server_error rather than leaking its text: the
// body goes to the client verbatim, and an unmapped internal error string could
// carry database or dependency detail.
func writeError(c *gin.Context, err error) {
	var oauthErr *oauth.Error
	if !errors.As(err, &oauthErr) {
		c.JSON(http.StatusInternalServerError, errorResponse{
			Error:            oauth.ErrorServerError,
			ErrorDescription: "服务器内部错误",
		})
		return
	}
	status := statusForKind(oauthErr.Kind)
	if oauthErr.RetryAfter > 0 {
		c.Header("Retry-After", retryAfterSeconds(oauthErr.RetryAfter))
	}
	// No WWW-Authenticate on a 401 here. RFC 6749 §5.2 requires the header only "if
	// the client attempted to authenticate via the Authorization request header
	// field", and this server never reads that header on the token or revocation
	// endpoints: credentials arrive as form parameters, and the discovery document
	// advertises exactly none and client_secret_post. Emitting a Basic challenge told
	// a conforming client to retry with an auth method that does not exist here — it
	// would resend the secret over Basic, omit the form client_id, and then fail with
	// "client_id 不能为空" on every attempt.
	c.JSON(status, errorResponse{
		Error:            oauthErr.Code,
		ErrorDescription: oauthErr.Description,
	})
}

// writeBearerError renders an error in RFC 6750 §3 form, for UserInfo.
//
// The distinguishing part is the WWW-Authenticate challenge: RFC 6750 requires
// the scheme to be Bearer and the error code to appear in the header as well as
// the body, which is what a conforming OIDC client reads to decide whether to
// refresh its token.
func writeBearerError(c *gin.Context, err error) {
	var oauthErr *oauth.Error
	if !errors.As(err, &oauthErr) {
		c.JSON(http.StatusInternalServerError, errorResponse{
			Error:            oauth.ErrorServerError,
			ErrorDescription: "服务器内部错误",
		})
		return
	}
	status := statusForKind(oauthErr.Kind)
	if oauthErr.RetryAfter > 0 {
		c.Header("Retry-After", retryAfterSeconds(oauthErr.RetryAfter))
	}
	if status == http.StatusUnauthorized {
		c.Header("WWW-Authenticate", bearerChallenge(oauthErr))
	}
	c.JSON(status, errorResponse{
		Error:            oauthErr.Code,
		ErrorDescription: oauthErr.Description,
	})
}

// bearerChallenge builds an RFC 6750 §3 challenge.
//
// Both quoted values are sanitized rather than merely assumed safe. Today every
// code and description is a service-authored constant, but this string becomes a
// response header: a stray quote would let a value escape its parameter and forge
// another, and a CR or LF would split the header. Enforcing it here means a future
// caller that passes request-derived text cannot turn it into header injection.
//
// error_description is dropped entirely when sanitizing leaves nothing usable,
// which is what happens to this service's Chinese messages: RFC 6750 §3 restricts
// a quoted challenge value to %x20-21 / %x23-5B / %x5D-7E, so a client validating
// against that grammar may discard the whole header — including the error code it
// needs to decide whether to refresh. The full message still travels in the JSON
// body, where UTF-8 is fine.
func bearerChallenge(err *oauth.Error) string {
	challenge := `Bearer realm="sast-link", error="` + quotedHeaderValue(err.Code) + `"`
	// Included only when the description was already conforming, rather than in
	// sanitized form. Stripping the non-ASCII bytes out of "Access Token 无效或已过期"
	// would emit "Access Token " — a truncated fragment that reads like a different
	// message. An absent optional parameter is honest; a mangled one is not.
	if description := quotedHeaderValue(err.Description); description == err.Description && description != "" {
		challenge += `, error_description="` + description + `"`
	}
	return challenge
}

// quotedHeaderValue reduces a value to the characters RFC 6750 §3 permits inside a
// challenge's quoted string: printable US-ASCII minus the quote and backslash
// delimiters. Anything else — control bytes that would split the header, and
// non-ASCII that would violate the grammar — is dropped.
func quotedHeaderValue(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '"' || r == '\\':
			return -1
		case r < 0x20 || r >= 0x7f:
			return -1
		default:
			return r
		}
	}, value)
}

// statusForKind maps a service failure to its HTTP status.
//
// invalid_client on 401 rather than 400 is required by RFC 6749 §5.2; every other
// token-endpoint error is a 400. Rate limiting and dependency outages are not
// RFC 6749 conditions, so they keep the HTTP semantics the rest of the API uses.
func statusForKind(kind oauth.Kind) int {
	switch kind {
	case oauth.KindInvalidClient, oauth.KindInvalidToken:
		return http.StatusUnauthorized
	case oauth.KindAccessDenied:
		return http.StatusForbidden
	case oauth.KindRateLimited:
		return http.StatusTooManyRequests
	case oauth.KindDependencyUnavailable:
		return http.StatusServiceUnavailable
	case oauth.KindInternal:
		return http.StatusInternalServerError
	case oauth.KindInvalidRequest, oauth.KindInvalidGrant:
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

func retryAfterSeconds(retryAfter time.Duration) string {
	seconds := retryAfter / time.Second
	if retryAfter%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	return strconv.FormatInt(int64(seconds), 10)
}
