package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	refreshTokenPrefix    = "rt_"
	refreshTokenBytes     = 32
	minimumHMACSecretSize = 32
)

// RefreshTokenManager creates opaque refresh tokens and independent HMAC hashes.
type RefreshTokenManager struct {
	Random RandomSource
	Secret []byte
}

// NewRefreshToken returns a high-entropy opaque refresh token with the rt_ prefix.
func (m RefreshTokenManager) NewRefreshToken() (string, error) {
	if len(m.Secret) < minimumHMACSecretSize {
		return "", ErrInvalidInput
	}
	random, err := randomBytes(m.Random, refreshTokenBytes)
	if err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	return refreshTokenPrefix + base64.RawURLEncoding.EncodeToString(random), nil
}

// HashRefreshToken returns an HMAC-SHA256 hash suitable for durable storage.
func (m RefreshTokenManager) HashRefreshToken(token string) (string, error) {
	if len(m.Secret) < minimumHMACSecretSize || !strings.HasPrefix(token, refreshTokenPrefix) {
		return "", ErrInvalidInput
	}
	mac := hmac.New(sha256.New, m.Secret)
	_, _ = mac.Write([]byte(token))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifyRefreshTokenHash verifies the token hash in constant time.
func (m RefreshTokenManager) VerifyRefreshTokenHash(token, expectedHash string) error {
	actualHash, err := m.HashRefreshToken(token)
	if err != nil {
		return err
	}
	actual, err := base64.RawURLEncoding.DecodeString(actualHash)
	if err != nil {
		return ErrInvalidInput
	}
	expected, err := base64.RawURLEncoding.DecodeString(expectedHash)
	if err != nil {
		return ErrInvalidInput
	}
	if hmac.Equal(actual, expected) {
		return nil
	}
	return ErrInvalidSecret
}
