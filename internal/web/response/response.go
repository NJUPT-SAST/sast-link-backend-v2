// Package response provides the standardized JSON response envelope.
package response

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
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
}

// Error implements the error interface.
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

// Error writes an error response. Unknown errors are mapped to 50000.
func Error(c *gin.Context, err error) {
	var be *BusinessError
	if errors.As(err, &be) {
		c.JSON(be.HTTPStatus, Response{
			Code:    be.Code,
			Message: be.Message,
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusInternalServerError, Response{
		Code:    50000,
		Message: "internal server error",
		Data:    nil,
	})
}
