package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	// #nosec G101 -- version marker, not a credential.
	clientSecretHashVersion = "sha256-v1"
	clientSecretBytes       = 32
)

// ClientSecretHasher generates and verifies OAuth client secrets.
//
// A client secret is 32 bytes from crypto/rand, so a plain SHA-256 hash suffices:
// there is no dictionary to walk and PBKDF2 would only add a CPU-bound step to
// every /oauth/token request. The hash protects against database disclosure (a
// leaked hash cannot be replayed as the credential) and compares in constant
// time.
type ClientSecretHasher struct {
	Random RandomSource
}

// NewClientSecret returns a fresh high-entropy secret and its storable hash. The
// plaintext is returned once, for display to the registering administrator; only
// the hash is ever persisted.
func (h ClientSecretHasher) NewClientSecret() (secret string, encodedHash string, err error) {
	random, err := randomBytes(h.Random, clientSecretBytes)
	if err != nil {
		return "", "", fmt.Errorf("generate client secret: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(random)
	return secret, HashClientSecret(secret), nil
}

// HashClientSecret returns the versioned, storable hash of a client secret.
func HashClientSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return clientSecretHashVersion + "$" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyClientSecret compares a presented secret against a stored hash in
// constant time.
//
// An empty presented secret is rejected before hashing, so a client that sends
// no client_secret at all fails authentication rather than matching a
// misconfigured row's hash of the empty string.
func VerifyClientSecret(secret, encodedHash string) error {
	if secret == "" {
		return ErrInvalidInput
	}
	version, expected, found := strings.Cut(encodedHash, "$")
	if !found {
		return ErrInvalidInput
	}
	if version != clientSecretHashVersion {
		return ErrUnsupportedVersion
	}
	expectedSum, err := base64.RawURLEncoding.DecodeString(expected)
	if err != nil || len(expectedSum) != sha256.Size {
		return ErrInvalidInput
	}
	actualSum := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(actualSum[:], expectedSum) != 1 {
		return ErrInvalidSecret
	}
	return nil
}
