// Package response provides unified JSON response helpers for Gin handlers.
//
// All endpoints (except OAuth 2.1 RFC 6749 endpoints) use the envelope:
//
//	{"code": 0, "message": "ok", "data": {...}}
package response

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
)

// Envelope is the unified API response envelope.
type Envelope struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

// OK sends a successful response (code=0, message="ok").
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Envelope{
		Code:    int(domain.Success),
		Message: "ok",
		Data:    data,
	})
}

// Created sends a 201 created response.
func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, Envelope{
		Code:    int(domain.Success),
		Message: "ok",
		Data:    data,
	})
}

// Err sends an error response with the HTTP status derived from the error code.
// Error codes follow the pattern {HTTPStatus}{sequence} (e.g. 40105 → HTTP 401).
func Err(c *gin.Context, code domain.ErrCode, msg string) {
	httpStatus := int(code) / 100
	if httpStatus < 400 || httpStatus > 599 {
		httpStatus = http.StatusInternalServerError
	}
	c.JSON(httpStatus, Envelope{
		Code:    int(code),
		Message: msg,
		Data:    nil,
	})
}

// ErrWithStatus sends an error response with a specific HTTP status code.
func ErrWithStatus(c *gin.Context, httpStatus int, code domain.ErrCode, msg string) {
	c.JSON(httpStatus, Envelope{
		Code:    int(code),
		Message: msg,
		Data:    nil,
	})
}

// MessageData is a convenience struct for message-only data payloads.
type MessageData struct {
	Message string `json:"message"`
}
