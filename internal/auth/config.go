package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// JWTConfig contains validated RS256 signing and verification settings.
type JWTConfig struct {
	Issuer         string
	Audience       string
	ActiveKID      string
	ActiveKeyPEM   string
	PreviousKID    string
	PreviousKeyPEM string
	Clock          Clock
}

// NewJWTManager parses RSA key material and constructs a strict JWT manager.
func NewJWTManager(config JWTConfig) (*JWTManager, error) {
	issuer := strings.TrimSpace(config.Issuer)
	audience := strings.TrimSpace(config.Audience)
	activeKID := strings.TrimSpace(config.ActiveKID)
	activeKeyPEM := strings.TrimSpace(config.ActiveKeyPEM)
	if issuer == "" || audience == "" || activeKID == "" || activeKeyPEM == "" {
		return nil, ErrInvalidInput
	}
	if (config.PreviousKID == "") != (config.PreviousKeyPEM == "") {
		return nil, ErrInvalidInput
	}

	active, err := parseRSAPrivateKey(activeKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse active JWT key: %w", err)
	}
	if active.N.BitLen() < 2048 {
		return nil, fmt.Errorf("parse active JWT key: %w", ErrInvalidInput)
	}
	manager := &JWTManager{
		Issuer:   issuer,
		Audience: []string{audience},
		Active:   JWTKeyPair{KID: activeKID, Private: active},
		Clock:    config.Clock,
	}
	if config.PreviousKeyPEM != "" {
		previousKeyPEM := strings.TrimSpace(config.PreviousKeyPEM)
		previousKID := strings.TrimSpace(config.PreviousKID)
		previous, err := parseRSAPublicKey(previousKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse previous JWT key: %w", err)
		}
		if previous.N.BitLen() < 2048 || previousKID == activeKID {
			return nil, fmt.Errorf("parse previous JWT key: %w", ErrInvalidInput)
		}
		manager.Previous = []JWTKeyPair{{KID: previousKID, Public: previous}}
	}
	return manager, nil
}

// NewRefreshTokenManager validates HMAC material and constructs a token manager.
func NewRefreshTokenManager(secret string, random RandomSource) (*RefreshTokenManager, error) {
	if len(secret) < minimumHMACSecretSize {
		return nil, ErrInvalidInput
	}
	return &RefreshTokenManager{Random: random, Secret: []byte(secret)}, nil
}

func parseRSAPrivateKey(encoded string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(normalizePEM(encoded)))
	if block == nil {
		return nil, ErrInvalidInput
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		private, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidInput
		}
		if err := private.Validate(); err != nil {
			return nil, ErrInvalidInput
		}
		return private, nil
	}
	private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrInvalidInput
	}
	if err := private.Validate(); err != nil {
		return nil, ErrInvalidInput
	}
	return private, nil
}

func parseRSAPublicKey(encoded string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(normalizePEM(encoded)))
	if block == nil {
		return nil, ErrInvalidInput
	}
	if public, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		rsaPublic, ok := public.(*rsa.PublicKey)
		if !ok {
			return nil, ErrInvalidInput
		}
		return rsaPublic, nil
	}
	if private, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaPrivate, ok := private.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidInput
		}
		return &rsaPrivate.PublicKey, nil
	}
	if private, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return &private.PublicKey, nil
	}
	public, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return public, nil
}

func normalizePEM(encoded string) string {
	return strings.ReplaceAll(encoded, `\n`, "\n")
}
