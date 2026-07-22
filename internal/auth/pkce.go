package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"unicode"
)

const (
	pkceMinVerifierLength = 43
	pkceMaxVerifierLength = 128
	pkceMethodS256        = "S256"
)

// ValidatePKCEVerifier applies RFC 7636 verifier syntax rules.
func ValidatePKCEVerifier(verifier string) error {
	if len(verifier) < pkceMinVerifierLength || len(verifier) > pkceMaxVerifierLength {
		return ErrInvalidInput
	}
	for _, character := range verifier {
		if character > unicode.MaxASCII || (!isPKCEAlphaNumeric(character) && !strings.ContainsRune("-._~", character)) {
			return ErrInvalidInput
		}
	}
	return nil
}

// PKCEChallengeS256 computes a base64url-encoded SHA-256 code challenge.
func PKCEChallengeS256(verifier string) (string, error) {
	if err := ValidatePKCEVerifier(verifier); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// VerifyPKCES256 verifies S256-only PKCE input.
func VerifyPKCES256(verifier, challenge, method string) error {
	if method != pkceMethodS256 {
		return ErrInvalidInput
	}
	actual, err := PKCEChallengeS256(verifier)
	if err != nil {
		return err
	}
	if actual != challenge {
		return ErrInvalidSecret
	}
	return nil
}

func isPKCEAlphaNumeric(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}
