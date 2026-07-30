package oauthhandler

import (
	"errors"
	"mime"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

// maxFormRequestBodyBytes bounds a token or revoke request body. These carry a
// handful of short parameters, so anything larger is malformed or hostile.
const maxFormRequestBodyBytes int64 = 16 << 10

// The decode failures. These strings reach the client as error_description, so
// each is a fixed, self-authored message: never a wrapped parser error, whose text
// would echo request bytes into a response body and a WWW-Authenticate header.
// formErrorDescription enforces that at the boundary.
var (
	errInvalidFormContentType = errors.New("request Content-Type must be application/x-www-form-urlencoded")
	errMalformedForm          = errors.New("request body is not a valid urlencoded form")
	errRepeatedFormParameter  = errors.New("request repeats a form parameter")
)

// formErrorDescription maps a decode failure to a description safe to return.
//
// An unrecognized error collapses to a generic message rather than its text: the
// description is echoed in an RFC 6749 body and, on 401, inside a quoted
// WWW-Authenticate parameter, so any request-derived bytes there would be both an
// information leak and a header-injection vector.
func formErrorDescription(err error) string {
	switch {
	case errors.Is(err, errInvalidFormContentType):
		return "请求 Content-Type 必须为 application/x-www-form-urlencoded"
	case errors.Is(err, errMalformedForm):
		return "请求体不是合法的 urlencoded 表单"
	case errors.Is(err, errRepeatedFormParameter):
		return "请求包含重复的表单参数"
	default:
		return "请求参数无效"
	}
}

// decodeStrictForm parses an RFC 6749 form body.
//
// The Content-Type check is deliberate rather than relying on Gin's binding: the
// spec requires this media type on the token and revocation endpoints, and
// accepting a JSON body would let a client succeed against this server and fail
// against any conforming one.
//
// Repeated parameters are rejected instead of resolved to the first or last
// occurrence. RFC 6749 §3.2 forbids them, and silently picking one makes the
// server's view of, say, two scope or client_id values differ from that of a proxy
// or gateway on the path — the classic parameter-smuggling gap.
func decodeStrictForm(c *gin.Context) (url.Values, error) {
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return nil, errInvalidFormContentType
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxFormRequestBodyBytes)
	if err := c.Request.ParseForm(); err != nil {
		return nil, errMalformedForm
	}
	// PostForm holds only the body, not the query string. A token request must not
	// be satisfiable by query parameters: those land in access logs and browser
	// history, which is exactly where a code or refresh token must not appear.
	values := c.Request.PostForm
	for _, list := range values {
		if len(list) > 1 {
			return nil, errRepeatedFormParameter
		}
	}
	return values, nil
}
