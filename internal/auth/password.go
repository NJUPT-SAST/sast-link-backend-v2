package auth

import (
	"crypto/pbkdf2"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

const (
	// #nosec G101 -- version marker, not a credential.
	passwordHashVersion    = "pbkdf2-sha512-v1"
	passwordHashIterations = 600_000
	passwordSaltBytes      = 16
	passwordKeyBytes       = 64
)

// PasswordHasher hashes and verifies passwords using PBKDF2-SHA512.
type PasswordHasher struct {
	Random RandomSource
}

// HashPassword returns a versioned PBKDF2-SHA512 password hash.
func (h PasswordHasher) HashPassword(password string) (string, error) {
	if password == "" {
		return "", ErrInvalidInput
	}
	salt, err := randomBytes(h.Random, passwordSaltBytes)
	if err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key, err := pbkdf2.Key(sha512.New, password, salt, passwordHashIterations, passwordKeyBytes)
	if err != nil {
		return "", fmt.Errorf("derive password hash: %w", err)
	}
	return strings.Join([]string{
		passwordHashVersion,
		strconv.Itoa(passwordHashIterations),
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(key),
	}, "$"), nil
}

// VerifyPassword verifies a password against a versioned hash in constant time.
func (h PasswordHasher) VerifyPassword(password, encodedHash string) error {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 4 {
		return ErrInvalidInput
	}
	if parts[0] != passwordHashVersion {
		return ErrUnsupportedVersion
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations != passwordHashIterations {
		return ErrInvalidInput
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(salt) != passwordSaltBytes {
		return ErrInvalidInput
	}
	expected, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(expected) != passwordKeyBytes {
		return ErrInvalidInput
	}
	actual, err := pbkdf2.Key(sha512.New, password, salt, iterations, len(expected))
	if err != nil {
		return fmt.Errorf("derive password verification hash: %w", err)
	}
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return ErrInvalidSecret
	}
	return nil
}
