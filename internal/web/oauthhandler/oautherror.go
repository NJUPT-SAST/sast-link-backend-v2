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
	// RFC 6749 §5.2: a 401 from the token endpoint must carry a challenge so the
	// client knows the failure was about its own credentials.
	if status == http.StatusUnauthorized {
		c.Header("WWW-Authenticate", `Basic realm="oauth", charset="UTF-8"`)
	}
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

// bearerChallenge builds an RFC 6750 §3 challenge. Quoted values are escaped by
// construction: the code comes from a fixed set of constants and the description
// is service-authored, so neither can contain a quote.
func bearerChallenge(err *oauth.Error) string {
	challenge := `Bearer realm="sast-link", error="` + err.Code + `"`
	if err.Description != "" {
		challenge += `, error_description="` + err.Description + `"`
	}
	return challenge
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
