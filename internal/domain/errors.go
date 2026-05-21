package domain

import "fmt"

// ErrCode is the unified error code type.
// All codes are 5-digit integers, fully compatible with the legacy backend.
type ErrCode int

const (
	// Success is the success code compatible with the legacy backend.
	Success ErrCode = 200

	// ErrInvalidParams indicates request parameter errors.
	ErrInvalidParams ErrCode = 10001
	// ErrUsernameInvalid indicates the username is incorrect.
	ErrUsernameInvalid ErrCode = 10002
	// ErrPasswordFormat indicates the password format is invalid.
	ErrPasswordFormat ErrCode = 10003
	// ErrPasswordEmpty indicates the password is empty.
	ErrPasswordEmpty ErrCode = 10004
	// ErrLoginFailed indicates login authentication failure.
	ErrLoginFailed ErrCode = 10005
	// ErrAccountExists indicates duplicate registration.
	ErrAccountExists ErrCode = 10007
	// ErrOAuthNotBound indicates the OAuth user is not registered or bound.
	ErrOAuthNotBound ErrCode = 10010
	// ErrUserNotFound indicates the user does not exist.
	ErrUserNotFound ErrCode = 10011

	// ErrTokenExpired indicates the token has expired.
	ErrTokenExpired ErrCode = 20002
	// ErrTokenGenFailed indicates token generation failure.
	ErrTokenGenFailed ErrCode = 20003
	// ErrTokenInvalid indicates the token is invalid.
	ErrTokenInvalid ErrCode = 20004
	// ErrTokenParseFail indicates token parsing failure.
	ErrTokenParseFail ErrCode = 20006
	// ErrTicketInvalid indicates the ticket is incorrect.
	ErrTicketInvalid ErrCode = 20007
	// ErrTicketNotFound indicates the ticket does not exist.
	ErrTicketNotFound ErrCode = 20008

	// ErrEmailSendFailed indicates email sending failure.
	ErrEmailSendFailed ErrCode = 30001
	// ErrCaptchaInvalid indicates the verification code is wrong.
	ErrCaptchaInvalid ErrCode = 30002
	// ErrEmailFormat indicates the email format is invalid.
	ErrEmailFormat ErrCode = 30003

	// ErrVerifyAccountFail indicates account verification failure.
	ErrVerifyAccountFail ErrCode = 40001
	// ErrVerifyPasswordFail indicates account password verification failure.
	ErrVerifyPasswordFail ErrCode = 40002

	// ErrInternal is the catch-all unknown server error.
	ErrInternal ErrCode = 50000

	// ErrOAuthClientErr indicates an OAuth client error.
	ErrOAuthClientErr ErrCode = 60001
	// ErrOAuthAccessTokenErr indicates an OAuth access token error.
	ErrOAuthAccessTokenErr ErrCode = 60002
	// ErrOAuthRefreshTokenErr indicates an OAuth refresh token error.
	ErrOAuthRefreshTokenErr ErrCode = 60003

	// ErrRegisterFail indicates registration failure due to stage error.
	ErrRegisterFail ErrCode = 70003
	// ErrResetPasswordFail indicates password reset failure.
	ErrResetPasswordFail ErrCode = 70004

	// ErrProfileNotFound indicates the user profile does not exist.
	ErrProfileNotFound ErrCode = 80000
	// ErrOrgIDInvalid indicates the organization ID is invalid.
	ErrOrgIDInvalid ErrCode = 80001
	// ErrHideFieldInvalid indicates a hide field value is invalid.
	ErrHideFieldInvalid ErrCode = 80002

	// ErrNotificationSendFail indicates audit notification sending failure.
	ErrNotificationSendFail ErrCode = 90000
	// ErrImageProcessFail indicates image processing failure.
	ErrImageProcessFail ErrCode = 90001
	// ErrImageURLInvalid indicates the image URL is invalid.
	ErrImageURLInvalid ErrCode = 90002
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
