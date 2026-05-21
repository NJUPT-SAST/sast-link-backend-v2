package response

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
)

// Response is the unified API response format.
type Response struct {
	ErrCode int    `json:"ErrCode"`
	ErrMsg  string `json:"ErrMsg"`
	Data    any    `json:"Data,omitempty"`
}

// OK sends a successful response.
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Response{
		ErrCode: int(domain.Success),
		ErrMsg:  "",
		Data:    data,
	})
}

// Err sends an error response.
func Err(c *gin.Context, code domain.ErrCode, msg string) {
	c.JSON(http.StatusOK, Response{
		ErrCode: int(code),
		ErrMsg:  msg,
		Data:    nil,
	})
}

// ErrWithStatus sends an error response with a specific HTTP status code.
func ErrWithStatus(c *gin.Context, httpStatus int, code domain.ErrCode, msg string) {
	c.JSON(httpStatus, Response{
		ErrCode: int(code),
		ErrMsg:  msg,
		Data:    nil,
	})
}
