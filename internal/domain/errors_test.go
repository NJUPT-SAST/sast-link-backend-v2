package domain

import (
	"errors"
	"testing"
)

func TestAppError_Error(t *testing.T) {
	cases := []struct {
		name string
		err  *AppError
		want string
	}{
		{
			name: "without cause",
			err:  NewError(ErrInvalidParams, "bad request"),
			want: "[40000] bad request",
		},
		{
			name: "with cause",
			err:  WrapError(ErrInternal, "something went wrong", errors.New("underlying")),
			want: "[50000] something went wrong: underlying",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.err.Error(); got != c.want {
				t.Errorf("Error() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestAppError_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := WrapError(ErrInternal, "wrapped", cause)

	if !errors.Is(err, cause) {
		t.Error("Unwrap() failed: errors.Is returned false")
	}

	plain := NewError(ErrInvalidParams, "plain")
	if plain.Unwrap() != nil {
		t.Error("NewError Unwrap() should return nil")
	}
}

func TestNewError(t *testing.T) {
	err := NewError(ErrPasswordWrong, "wrong password")
	if err.Code != ErrPasswordWrong {
		t.Errorf("Code = %d, want %d", err.Code, ErrPasswordWrong)
	}
	if err.Message != "wrong password" {
		t.Errorf("Message = %q, want wrong password", err.Message)
	}
	if err.Cause != nil {
		t.Error("Cause should be nil")
	}
}

func TestWrapError(t *testing.T) {
	cause := errors.New("cause")
	err := WrapError(ErrAccessTokenExpired, "token expired", cause)
	if err.Code != ErrAccessTokenExpired {
		t.Errorf("Code = %d, want %d", err.Code, ErrAccessTokenExpired)
	}
	if err.Cause != cause {
		t.Error("Cause mismatch")
	}
}

func TestSuccessCode(t *testing.T) {
	if Success != 0 {
		t.Errorf("Success code = %d, want 0", Success)
	}
}

func TestErrorCodesDistinct(t *testing.T) {
	codes := map[ErrCode]bool{
		Success:                   true,
		ErrInvalidParams:          true,
		ErrCaptchaInvalid:         true,
		ErrEmailDomainNotAllowed:  true,
		ErrNotLoggedIn:            true,
		ErrPasswordWrong:          true,
		ErrPermissionDenied:       true,
		ErrUserNotFound:           true,
		ErrEmailAlreadyRegistered: true,
		ErrPasswordTooShort:       true,
		ErrTooManyRequests:        true,
		ErrInternal:               true,
		ErrEmailSendFailed:        true,
		ErrDatabaseError:          true,
	}
	if len(codes) != 14 {
		t.Errorf("expected 14 distinct codes, got %d", len(codes))
	}
}
