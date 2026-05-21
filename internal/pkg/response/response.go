// Package response provides unified JSON response helpers for Gin handlers.
package response

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
)

// Response is the unified API response format.
type Response struct {
	Success bool   `json:"Success"`
	ErrCode int    `json:"ErrCode"`
	ErrMsg  string `json:"ErrMsg"`
	Data    any    `json:"Data,omitempty"`
}

// OK sends a successful response.
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Response{
		Success: true,
		ErrCode: int(domain.Success),
		ErrMsg:  "",
		Data:    data,
	})
}

// Err sends an error response.
func Err(c *gin.Context, code domain.ErrCode, msg string) {
	c.JSON(http.StatusOK, Response{
		Success: false,
		ErrCode: int(code),
		ErrMsg:  msg,
		Data:    nil,
	})
}

// ErrWithStatus sends an error response with a specific HTTP status code.
func ErrWithStatus(c *gin.Context, httpStatus int, code domain.ErrCode, msg string) {
	c.JSON(httpStatus, Response{
		Success: false,
		ErrCode: int(code),
		ErrMsg:  msg,
		Data:    nil,
	})
}
