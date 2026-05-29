package domain

import "fmt"

// ErrCode is the unified error code type.
// All codes are 5-digit integers, fully compatible with the legacy backend.
type ErrCode int

const (
	// Success is the success code compatible with the legacy backend.
	Success ErrCode = 200

	// --- 1xxxx: 请求/账号相关 ---

	// ErrInvalidParams indicates request parameter errors.
	ErrInvalidParams ErrCode = 10001
	// ErrUsernameInvalid indicates the username format is incorrect.
	ErrUsernameInvalid ErrCode = 10002
	// ErrPasswordFormat indicates the password format is invalid.
	ErrPasswordFormat ErrCode = 10003
	// ErrPasswordEmpty indicates the password is empty.
	ErrPasswordEmpty ErrCode = 10004
	// ErrLoginFailed indicates login failure (wrong password).
	ErrLoginFailed ErrCode = 10005
	// ErrAccountNotFound indicates the account does not exist.
	ErrAccountNotFound ErrCode = 10006
	// ErrAccountExists indicates the account already exists.
	ErrAccountExists ErrCode = 10007
	// ErrRateLimited indicates the operation is rate-limited.
	ErrRateLimited ErrCode = 10008
	// ErrPermissionDenied indicates insufficient permissions.
	ErrPermissionDenied ErrCode = 10009
	// ErrOAuthNotBound indicates the OAuth provider is not bound to any account.
	ErrOAuthNotBound ErrCode = 10010
	// ErrUserNotFound indicates the user does not exist.
	ErrUserNotFound ErrCode = 10011
	// ErrOAuthAlreadyBound indicates the OAuth provider is already bound to another account.
	ErrOAuthAlreadyBound ErrCode = 10012
	// ErrOAuthBindFailed indicates OAuth binding failed.
	ErrOAuthBindFailed ErrCode = 10013
	// ErrUnbindFailed indicates OAuth unbinding failed.
	ErrUnbindFailed ErrCode = 10014
	// ErrEmailAlreadyRegistered indicates the email is already registered.
	ErrEmailAlreadyRegistered ErrCode = 10015
	// ErrBindEmailLimitReached indicates the user has reached the max bound email count.
	ErrBindEmailLimitReached ErrCode = 10016
	// ErrEmailAlreadyBound indicates the email is already bound to another user.
	ErrEmailAlreadyBound ErrCode = 10017
	// ErrUnbindCooldown indicates the email is in the unbind cooldown period.
	ErrUnbindCooldown ErrCode = 10018

	// --- 2xxxx: Token/Ticket 相关 ---

	// ErrTokenExpired indicates the token has expired (generic).
	ErrTokenExpired ErrCode = 20001
	// ErrAccessTokenExpired indicates the access token has expired.
	ErrAccessTokenExpired ErrCode = 20002
	// ErrTokenGenFailed indicates token generation failure.
	ErrTokenGenFailed ErrCode = 20003
	// ErrTokenInvalid indicates the token is invalid.
	ErrTokenInvalid ErrCode = 20004
	// ErrRefreshTokenInvalid indicates the refresh token is invalid or expired.
	ErrRefreshTokenInvalid ErrCode = 20005
	// ErrTokenParseFail indicates token parsing failure.
	ErrTokenParseFail ErrCode = 20006
	// ErrTicketInvalid indicates the ticket is incorrect.
	ErrTicketInvalid ErrCode = 20007
	// ErrTicketNotFound indicates the ticket does not exist or has expired.
	ErrTicketNotFound ErrCode = 20008
	// ErrTokenVersionMismatch indicates token_version validation failed.
	ErrTokenVersionMismatch ErrCode = 20009

	// --- 3xxxx: 邮件/验证码相关 ---

	// ErrEmailSendFailed indicates email sending failure.
	ErrEmailSendFailed ErrCode = 30001
	// ErrCaptchaInvalid indicates the verification code is wrong.
	ErrCaptchaInvalid ErrCode = 30002
	// ErrEmailFormat indicates the email format is invalid.
	ErrEmailFormat ErrCode = 30003
	// ErrBindEmailCaptchaInvalid indicates bind-email captcha is wrong.
	ErrBindEmailCaptchaInvalid ErrCode = 30004
	// ErrBindEmailTicketInvalid indicates the BindEmail-Ticket is invalid or expired.
	ErrBindEmailTicketInvalid ErrCode = 30005
	// ErrUnbindCaptchaInvalid indicates unbind-email captcha is wrong.
	ErrUnbindCaptchaInvalid ErrCode = 30006

	// --- 4xxxx: 账号/密码验证相关 ---

	// ErrVerifyAccountFail indicates account verification failure.
	ErrVerifyAccountFail ErrCode = 40001
	// ErrVerifyPasswordFail indicates password verification failure.
	ErrVerifyPasswordFail ErrCode = 40002
	// ErrOldPasswordWrong indicates the old password is incorrect.
	ErrOldPasswordWrong ErrCode = 40003

	// --- 5xxxx: 服务端错误 ---

	// ErrInternal is the catch-all unknown server error.
	ErrInternal ErrCode = 50000

	// --- 6xxxx: OAuth 2.1 标准错误 ---

	// ErrInvalidRequest indicates an OAuth 2.1 invalid_request error.
	ErrInvalidRequest ErrCode = 60001
	// ErrInvalidClient indicates an OAuth 2.1 invalid_client error.
	ErrInvalidClient ErrCode = 60002
	// ErrInvalidGrant indicates an OAuth 2.1 invalid_grant error.
	ErrInvalidGrant ErrCode = 60003
	// ErrUnauthorizedClient indicates an OAuth 2.1 unauthorized_client error.
	ErrUnauthorizedClient ErrCode = 60004
	// ErrUnsupportedGrantType indicates an OAuth 2.1 unsupported_grant_type error.
	ErrUnsupportedGrantType ErrCode = 60005
	// ErrInvalidScope indicates an OAuth 2.1 invalid_scope error.
	ErrInvalidScope ErrCode = 60006
	// ErrServerError indicates an OAuth 2.1 server_error.
	ErrServerError ErrCode = 60007
	// ErrTemporarilyUnavailable indicates an OAuth 2.1 temporarily_unavailable error.
	ErrTemporarilyUnavailable ErrCode = 60008

	// --- 7xxxx: 注册/重置相关 ---

	// ErrRegistrationIncomplete indicates required fields are missing during registration.
	ErrRegistrationIncomplete ErrCode = 70001
	// ErrRegistrationStageFail indicates a generic registration stage error.
	ErrRegistrationStageFail ErrCode = 70002
	// ErrResetPasswordFail indicates password reset failure.
	ErrResetPasswordFail ErrCode = 70004
	// ErrOAuthRegistrationCompletionFail indicates OAuth registration completion failure.
	ErrOAuthRegistrationCompletionFail ErrCode = 70005

	// --- 8xxxx: 用户资料相关 ---

	// ErrProfileNotFound indicates the user profile does not exist.
	ErrProfileNotFound ErrCode = 80000
	// ErrOrgIDInvalid indicates the organization ID is invalid.
	ErrOrgIDInvalid ErrCode = 80001
	// ErrHideFieldInvalid indicates a hide field value is invalid.
	ErrHideFieldInvalid ErrCode = 80002
	// ErrEmailBindFailed indicates email binding failed.
	ErrEmailBindFailed ErrCode = 80003

	// --- 9xxxx: 通知/文件相关 ---

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
