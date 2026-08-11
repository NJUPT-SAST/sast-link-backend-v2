package sessionhandler

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

// avatarUploadResponse mirrors the PRD §4.9 / openapi.yaml contract: the public
// URL of the stored avatar.
type avatarUploadResponse struct {
	AvatarURL string `json:"avatar_url"`
}

// maxAvatarRequestBodySize bounds the multipart body before parsing. c.FormFile
// reads the entire stream (spilling to a temp file past Gin's in-memory cap), so
// without this an oversized body would be fully received before the service's
// 1MB check runs. The ceiling leaves room for multipart framing on top of a
// legitimate 1MB file; a body past it fails multipart parsing and answers 40000.
const maxAvatarRequestBodySize = 1<<20 + 1<<20

// UploadAvatar handles PUT /user/avatar. The multipart body is parsed here —
// the file part is passed to the service as a stream, so every size and format
// rule lives in the service and is testable without HTTP.
func (h Handler) UploadAvatar(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	// Bound the request body before any multipart parsing: see
	// maxAvatarRequestBodySize for why the service-side limit alone is not enough.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAvatarRequestBodySize)
	fileHeader, err := c.FormFile("file")
	if err != nil {
		// A missing or malformed file part is a client error, not a server fault:
		// the contract requires exactly one "file" field.
		response.Error(c, badRequest())
		return
	}
	file, err := fileHeader.Open()
	if err != nil {
		slog.ErrorContext(c.Request.Context(), "open avatar upload part", "error", err)
		response.Error(c, internalError())
		return
	}
	defer func() { _ = file.Close() }()

	result, err := h.Service.UploadAvatar(c.Request.Context(), session.UploadAvatarInput{
		UserID:    principal.UserID,
		Filename:  fileHeader.Filename,
		Content:   file,
		Size:      fileHeader.Size,
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, avatarUploadResponse{AvatarURL: result.AvatarURL})
}
