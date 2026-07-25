// Package response provides the standardized JSON response envelope.
package response

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
)

// Response is the standard API response envelope.
type Response struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

// BusinessError carries an HTTP status code and a business error code.
type BusinessError struct {
	HTTPStatus int
	Code       int
	Message    string
	RetryAfter time.Duration
}

// Error returns the error message.
func (e *BusinessError) Error() string {
	return e.Message
}

// Ok writes a successful response with the given data.
func Ok(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Response{
		Code:    0,
		Message: "ok",
		Data:    data,
	})
}

// Error writes an error response. Unknown errors are mapped to CodeInternal.
func Error(c *gin.Context, err error) {
	var be *BusinessError
	if errors.As(err, &be) {
		if be.RetryAfter > 0 {
			seconds := be.RetryAfter / time.Second
			if be.RetryAfter%time.Second != 0 {
				seconds++
			}
			c.Header("Retry-After", strconv.FormatInt(int64(seconds), 10))
		}
		c.JSON(be.HTTPStatus, Response{
			Code:    be.Code,
			Message: be.Message,
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusInternalServerError, Response{
		Code:    errcode.CodeInternal,
		Message: "服务器内部错误",
		Data:    nil,
	})
}
