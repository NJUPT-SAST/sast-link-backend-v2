package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// JWTConfig contains validated EdDSA signing and verification settings.
type JWTConfig struct {
	Issuer         string
	Audience       string
	ActiveKID      string
	ActiveKeyPEM   string
	PreviousKID    string
	PreviousKeyPEM string
	Clock          Clock
}

// NewJWTManager parses Ed25519 key material and constructs a strict JWT manager.
// EdDSA/Ed25519 signs roughly an order of magnitude faster than the RSA-2048 the
// service used before — a real cost on the 1c1g deployment, where every
// login/refresh issues a JWT and every authenticated request verifies one.
func NewJWTManager(config JWTConfig) (*JWTManager, error) {
	issuer := strings.TrimSpace(config.Issuer)
	audience := strings.TrimSpace(config.Audience)
	activeKID := strings.TrimSpace(config.ActiveKID)
	activeKeyPEM := strings.TrimSpace(config.ActiveKeyPEM)
	if issuer == "" || audience == "" || activeKID == "" || activeKeyPEM == "" {
		return nil, ErrInvalidInput
	}
	previousKID := strings.TrimSpace(config.PreviousKID)
	previousKeyPEM := strings.TrimSpace(config.PreviousKeyPEM)
	if (previousKID == "") != (previousKeyPEM == "") {
		return nil, ErrInvalidInput
	}

	active, err := parseEd25519PrivateKey(activeKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse active JWT key: %w", err)
	}
	manager := &JWTManager{
		Issuer:   issuer,
		Audience: []string{audience},
		Active:   JWTKeyPair{KID: activeKID, Private: active},
		Clock:    config.Clock,
	}
	if previousKeyPEM != "" {
		previous, err := parseEd25519PublicKey(previousKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse previous JWT key: %w", err)
		}
		if previousKID == activeKID {
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

func parseEd25519PrivateKey(encoded string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(normalizePEM(encoded)))
	if block == nil {
		return nil, ErrInvalidInput
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrInvalidInput
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, ErrInvalidInput
	}
	return private, nil
}

func parseEd25519PublicKey(encoded string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(normalizePEM(encoded)))
	if block == nil {
		return nil, ErrInvalidInput
	}
	if public, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		edPublic, ok := public.(ed25519.PublicKey)
		if !ok || len(edPublic) != ed25519.PublicKeySize {
			return nil, ErrInvalidInput
		}
		return edPublic, nil
	}
	if private, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		edPrivate, ok := private.(ed25519.PrivateKey)
		if !ok {
			return nil, ErrInvalidInput
		}
		public, ok := edPrivate.Public().(ed25519.PublicKey)
		if !ok || len(public) != ed25519.PublicKeySize {
			return nil, ErrInvalidInput
		}
		return public, nil
	}
	return nil, ErrInvalidInput
}

func normalizePEM(encoded string) string {
	return strings.ReplaceAll(encoded, `\n`, "\n")
}
