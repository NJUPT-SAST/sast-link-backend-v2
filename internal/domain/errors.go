package domain

import "fmt"

// ErrCode is the unified error code type.
type ErrCode int

const (
	// Success code — old backend compatibility.
	Success ErrCode = 200

	// General errors (1xxxx).
	ErrInternalError      ErrCode = 10001
	ErrInvalidParams      ErrCode = 10002
	ErrUnauthorized       ErrCode = 10003
	ErrNotFound           ErrCode = 10004
	ErrTooManyRequests    ErrCode = 10005
	ErrServiceUnavailable ErrCode = 10006

	// Auth errors (2xxxx).
	ErrAccountNotFound      ErrCode = 20001
	ErrPasswordIncorrect    ErrCode = 20002
	ErrAccountAlreadyExists ErrCode = 20003
	ErrTicketInvalid        ErrCode = 20004
	ErrTicketExpired        ErrCode = 20005
	ErrTicketUsed           ErrCode = 20006
	ErrTokenInvalid         ErrCode = 20007
	ErrTokenExpired         ErrCode = 20008
	ErrPermissionDenied     ErrCode = 20009
	ErrOauthBindFailed      ErrCode = 20010
	ErrOauthAlreadyBound    ErrCode = 20011
	ErrOauthNotBound        ErrCode = 20012
	ErrCaptchaInvalid       ErrCode = 20013
	ErrEmailSendFailed      ErrCode = 20014
	ErrEmailAlreadyVerified ErrCode = 20015
	ErrVerificationInvalid  ErrCode = 20016
	ErrRoleForbidden        ErrCode = 20017
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
