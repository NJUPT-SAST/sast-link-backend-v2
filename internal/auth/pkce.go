package auth

import (
	"crypto/sha256"
	"crypto/subtle"
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

// VerifyPKCES256 verifies S256-only PKCE input; the comparison is constant time
// because the verifier is a secret.
func VerifyPKCES256(verifier, challenge, method string) error {
	if method != pkceMethodS256 {
		return ErrInvalidInput
	}
	actual, err := PKCEChallengeS256(verifier)
	if err != nil {
		return err
	}
	if len(actual) != len(challenge) || subtle.ConstantTimeCompare([]byte(actual), []byte(challenge)) != 1 {
		return ErrInvalidSecret
	}
	return nil
}

// IsValidPKCEChallenge reports whether a code challenge is a well-formed S256
// digest: 43 base64url characters, so a challenge no verifier can produce fails
// at authorize time as a fixable client error rather than at redemption.
func IsValidPKCEChallenge(challenge string) bool {
	if len(challenge) != base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return false
	}
	for _, character := range challenge {
		if character > unicode.MaxASCII || (!isPKCEAlphaNumeric(character) && character != '-' && character != '_') {
			return false
		}
	}
	return true
}

func isPKCEAlphaNumeric(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}
