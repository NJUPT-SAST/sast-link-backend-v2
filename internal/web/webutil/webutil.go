// Package webutil holds request-decoding and business-error helpers shared by
// the handler packages. Each handler package previously carried its own copy of
// DecodeStrictJSON and the BadRequest/InternalError factories; this is the
// single implementation they all delegate to, so a fix to the body policy lands
// once.
package webutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

// MaxJSONRequestBodyBytes caps a JSON request body. 64 KiB is generous for every
// current endpoint — the largest bodies are the alumni submission's dozen short
// strings and the admin user-update payloads — and the point is that a caller
// (an unauthenticated one above all) must not choose how much the service reads.
// The OAuth consent and grants endpoints used to read 8 KiB; merging them onto
// this constant is safe because their bodies are a handful of fields, and the
// cap exists to bound work, not to reject anything near either bound.
const MaxJSONRequestBodyBytes int64 = 64 << 10

var (
	// ErrInvalidJSONContentType is returned when a strict decoder finds the
	// request's Content-Type missing or not application/json.
	ErrInvalidJSONContentType = errors.New("request Content-Type must be application/json")
	// ErrTrailingJSONValue is returned when more than one JSON value follows the
	// decoded destination (e.g. `{} {}`), which strict decoders refuse.
	ErrTrailingJSONValue = errors.New("JSON request body contains multiple values")
)

// RequireJSONContentType rejects a request whose Content-Type is not
// application/json. It is the first half of DecodeStrictJSON, exported so a
// handler that must read the body before decoding (to accept an empty one) can
// apply the same rule without duplicating it.
func RequireJSONContentType(c *gin.Context) error {
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return ErrInvalidJSONContentType
	}
	return nil
}

// DecodeStrictJSON applies the shared strict request-body policy for JSON APIs:
// a required application/json Content-Type, a body bounded by
// MaxJSONRequestBodyBytes, no unknown fields, exactly one JSON value, and then
// binding validation. A violation surfaces as the inner error (io.EOF for an
// empty body, ErrInvalidJSONContentType, or a binding error); callers map it
// onto BadRequest.
func DecodeStrictJSON(c *gin.Context, destination any) error {
	if err := RequireJSONContentType(c); err != nil {
		return err
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxJSONRequestBodyBytes)
	return decodeJSON(json.NewDecoder(c.Request.Body), destination)
}

// DecodeStrictJSONBytes applies the unknown-fields, single-value and validation
// rules to an already-read body. Content-Type is deliberately not checked here:
// the caller decides whether the body exists first (see the alumni handler's
// optional strict decode), and the type rule has already run by the time bytes
// reach this function.
func DecodeStrictJSONBytes(body []byte, destination any) error {
	return decodeJSON(json.NewDecoder(bytes.NewReader(body)), destination)
}

// decodeJSON is the shared tail of both decoders: no unknown fields, exactly one
// JSON value (a second decode past EOF reveals trailing junk), then validation.
func decodeJSON(decoder *json.Decoder, destination any) error {
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrTrailingJSONValue
	}
	return binding.Validator.ValidateStruct(destination)
}

// BadRequest builds the standard envelope error for a malformed request.
func BadRequest() error {
	return &response.BusinessError{
		HTTPStatus: http.StatusBadRequest,
		Code:       errcode.CodeBadRequest,
		Message:    "请求参数错误",
	}
}

// InternalError builds the standard envelope error for an unexpected failure.
func InternalError() error {
	return &response.BusinessError{
		HTTPStatus: http.StatusInternalServerError,
		Code:       errcode.CodeInternal,
		Message:    "服务器内部错误",
	}
}

// NotFound builds a 404 envelope error for a named subject. Code and message are
// parameters because every caller names a different thing, and the business code
// is what keeps a missing alumni ticket (42207) apart from a missing OAuth client
// (40402) or a missing binding record (40400).
func NotFound(code int, message string) error {
	return &response.BusinessError{
		HTTPStatus: http.StatusNotFound,
		Code:       code,
		Message:    message,
	}
}
