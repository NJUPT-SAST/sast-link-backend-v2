package badgehandler

import (
	"errors"
	"net/http"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/badge"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

// mapServiceError turns a badge service error into the HTTP business error.
func mapServiceError(err error) error {
	var serviceErr *badge.Error
	if !errors.As(err, &serviceErr) {
		return err
	}

	message := defaultMessage(serviceErr.Kind)
	switch serviceErr.Code {
	case errcode.CodeBadgeAlreadyEnabled:
		message = errcode.Messages[errcode.CodeBadgeAlreadyEnabled]
	case errcode.CodeBadgeNicknameMissing:
		message = errcode.Messages[errcode.CodeBadgeNicknameMissing]
	case errcode.CodeUserNotFound:
		message = errcode.Messages[errcode.CodeUserNotFound]
	case errcode.CodeRateLimited:
		message = errcode.Messages[errcode.CodeRateLimited]
	}

	var status int
	switch serviceErr.Kind {
	case badge.KindInvalidInput:
		status = http.StatusBadRequest
	case badge.KindValidationFailed:
		status = http.StatusUnprocessableEntity
	case badge.KindNotFound:
		status = http.StatusNotFound
	case badge.KindConflict:
		status = http.StatusConflict
	case badge.KindRateLimited:
		status = http.StatusTooManyRequests
	default:
		status = http.StatusInternalServerError
	}

	return &response.BusinessError{
		HTTPStatus: status,
		Code:       serviceErr.Code,
		Message:    message,
		RetryAfter: serviceErr.RetryAfter,
	}
}

// defaultMessage is the fallback copy per Kind; code-specific wording above
// overrides it.
func defaultMessage(kind badge.Kind) string {
	switch kind {
	case badge.KindInvalidInput:
		return errcode.Messages[errcode.CodeBadRequest]
	case badge.KindValidationFailed:
		return errcode.Messages[errcode.CodeValidationFailed]
	case badge.KindNotFound:
		return errcode.Messages[errcode.CodeUserNotFound]
	case badge.KindConflict:
		return errcode.Messages[errcode.CodeConflict]
	case badge.KindRateLimited:
		return errcode.Messages[errcode.CodeRateLimited]
	default:
		return errcode.Messages[errcode.CodeInternal]
	}
}

func internalError() *response.BusinessError {
	return &response.BusinessError{
		HTTPStatus: http.StatusInternalServerError,
		Code:       errcode.CodeInternal,
		Message:    errcode.Messages[errcode.CodeInternal],
	}
}
