// Package auth contains authentication primitives shared by service layers.
package auth

import "errors"

var (
	// ErrInvalidInput reports malformed user-controlled input.
	ErrInvalidInput = errors.New("auth: invalid input")
	// ErrInvalidSecret reports a password, token, or verifier mismatch.
	ErrInvalidSecret = errors.New("auth: invalid secret")
	// ErrUnsupportedVersion reports an unknown versioned credential format.
	ErrUnsupportedVersion = errors.New("auth: unsupported version")
	// ErrExpiredToken reports an expired token. A not-yet-valid token (nbf or iat
	// in the future) is not expired and is reported as ErrInvalidToken instead.
	ErrExpiredToken = errors.New("auth: token is not active")
	// ErrInvalidToken reports a malformed token, a failed signature check, or a
	// not-yet-valid token.
	ErrInvalidToken = errors.New("auth: invalid token")
	// ErrRevokedToken reports an explicitly revoked token or family.
	ErrRevokedToken = errors.New("auth: token revoked")
	// ErrTokenReplay reports reuse of a one-time or rotated token.
	ErrTokenReplay = errors.New("auth: token replay")
	// ErrConflict reports an authentication resource conflict.
	ErrConflict = errors.New("auth: conflict")
)
