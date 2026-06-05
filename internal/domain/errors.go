package domain

import "fmt"

// ErrCode is the unified error code type (5-digit, HTTP-status-prefixed).
// 0 means success. Non-zero codes follow the pattern {HTTPStatus}{Sequence}.
type ErrCode int

const (
	// Success indicates a successful operation.
	Success ErrCode = 0

	// 400xx: parameter errors

	// ErrInvalidParams indicates request parameter errors.
	ErrInvalidParams ErrCode = 40000
	// ErrMissingRequiredParam indicates a required parameter is missing.
	ErrMissingRequiredParam ErrCode = 40001
	// ErrInvalidParamFormat indicates a parameter format is invalid.
	ErrInvalidParamFormat ErrCode = 40002
	// ErrCaptchaInvalid indicates the verification code is wrong.
	ErrCaptchaInvalid ErrCode = 40010
	// ErrCaptchaExpired indicates the verification code has expired.
	ErrCaptchaExpired ErrCode = 40011
	// ErrCaptchaRateLimited indicates captcha sending is rate-limited.
	ErrCaptchaRateLimited ErrCode = 40012
	// ErrEmailDomainNotAllowed indicates the email domain is not allowed.
	ErrEmailDomainNotAllowed ErrCode = 40020

	// 401xx: authentication errors

	// ErrNotLoggedIn indicates the user is not logged in (missing or invalid Authorization header).
	ErrNotLoggedIn ErrCode = 40100
	// ErrAccessTokenExpired indicates the access token has expired.
	ErrAccessTokenExpired ErrCode = 40101
	// ErrAccessTokenInvalid indicates the access token is invalid or has been revoked.
	ErrAccessTokenInvalid ErrCode = 40102
	// ErrRegisterTicketInvalid indicates the Register-Ticket is invalid or has expired.
	ErrRegisterTicketInvalid ErrCode = 40103
	// ErrBindTicketInvalid indicates the Bind-Ticket is invalid or has expired.
	ErrBindTicketInvalid ErrCode = 40104
	// ErrPasswordWrong indicates the password is incorrect.
	ErrPasswordWrong ErrCode = 40105
	// ErrLoginEmailNotFound indicates the login email does not exist.
	ErrLoginEmailNotFound ErrCode = 40106
	// ErrLoginCodeInvalid indicates the login_code is invalid or has expired.
	ErrLoginCodeInvalid ErrCode = 40107

	// 403xx: permission errors

	// ErrPermissionDenied indicates insufficient permissions.
	ErrPermissionDenied ErrCode = 40300
	// ErrAccountDeleted indicates the account has been deleted.
	ErrAccountDeleted ErrCode = 40301
	// ErrNotSASTLarkUser indicates the user is not a SAST enterprise Lark user.
	ErrNotSASTLarkUser ErrCode = 40302

	// 404xx: resource not found errors

	// ErrResourceNotFound indicates the requested resource does not exist.
	ErrResourceNotFound ErrCode = 40400
	// ErrUserNotFound indicates the user does not exist.
	ErrUserNotFound ErrCode = 40401
	// ErrOAuthClientNotFound indicates the OAuth client does not exist.
	ErrOAuthClientNotFound ErrCode = 40402

	// 409xx: resource conflict errors

	// ErrResourceAlreadyExists indicates the resource already exists.
	ErrResourceAlreadyExists ErrCode = 40900
	// ErrEmailAlreadyRegistered indicates the email is already registered.
	ErrEmailAlreadyRegistered ErrCode = 40901
	// ErrStudentIDAlreadyTaken indicates the student ID is already taken.
	ErrStudentIDAlreadyTaken ErrCode = 40902
	// ErrIdentityAlreadyBound indicates the third-party account is already bound to another user.
	ErrIdentityAlreadyBound ErrCode = 40903
	// ErrIdentityTypeAlreadyBound indicates this type of account is already bound.
	ErrIdentityTypeAlreadyBound ErrCode = 40904
	// ErrBindEmailLimitReached indicates the max number of bound emails (2) has been reached.
	ErrBindEmailLimitReached ErrCode = 40905

	// 422xx: business validation errors

	// ErrBusinessValidationFailed indicates a generic business validation failure.
	ErrBusinessValidationFailed ErrCode = 42200
	// ErrPasswordTooShort indicates the password is too short (minimum 8 characters).
	ErrPasswordTooShort ErrCode = 42201
	// ErrPasswordSameAsOld indicates the new password is the same as the old one.
	ErrPasswordSameAsOld ErrCode = 42202
	// ErrCannotUnbindOnlyLoginMethod indicates the only login method cannot be unbound.
	ErrCannotUnbindOnlyLoginMethod ErrCode = 42203

	// 429xx: rate limiting errors

	// ErrTooManyRequests indicates the request rate limit has been exceeded.
	ErrTooManyRequests ErrCode = 42900

	// 500xx: server errors

	// ErrInternal indicates an internal server error.
	ErrInternal ErrCode = 50000
	// ErrEmailSendFailed indicates email sending failed.
	ErrEmailSendFailed ErrCode = 50001
	// ErrObjectStorageUploadFailed indicates object storage upload failed.
	ErrObjectStorageUploadFailed ErrCode = 50002
	// ErrDatabaseError indicates a database error.
	ErrDatabaseError ErrCode = 50003
)

// AppError is the unified application error.
type AppError struct {
	Code    ErrCode
	Message string
	Cause   error
}

func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%d] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Cause
}

// NewError creates a new AppError.
func NewError(code ErrCode, message string) *AppError {
	return &AppError{Code: code, Message: message}
}

// WrapError wraps an existing error into an AppError.
func WrapError(code ErrCode, message string, cause error) *AppError {
	return &AppError{Code: code, Message: message, Cause: cause}
}
