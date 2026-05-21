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
			want: "[10001] bad request",
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
	err := NewError(ErrLoginFailed, "login failed")
	if err.Code != ErrLoginFailed {
		t.Errorf("Code = %d, want %d", err.Code, ErrLoginFailed)
	}
	if err.Message != "login failed" {
		t.Errorf("Message = %q, want login failed", err.Message)
	}
	if err.Cause != nil {
		t.Error("Cause should be nil")
	}
}

func TestWrapError(t *testing.T) {
	cause := errors.New("cause")
	err := WrapError(ErrTokenExpired, "token expired", cause)
	if err.Code != ErrTokenExpired {
		t.Errorf("Code = %d, want %d", err.Code, ErrTokenExpired)
	}
	if err.Cause != cause {
		t.Error("Cause mismatch")
	}
}
