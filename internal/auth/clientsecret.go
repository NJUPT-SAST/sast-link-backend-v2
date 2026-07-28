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
// This deliberately does not reuse PasswordHasher. PBKDF2 at 600k iterations
// exists to make a low-entropy, human-chosen password expensive to guess; it
// costs ~380ms per derivation. A client secret is 32 bytes from crypto/rand, so
// there is no dictionary to walk and no work factor worth buying — the only
// attack is exhausting a 256-bit space. Running PBKDF2 on it would add nothing
// but would put a 380ms CPU-bound step on every /oauth/token request from every
// third-party client, turning the token endpoint into the service's bottleneck.
//
// A plain SHA-256 over a high-entropy secret is the same reasoning used for
// storing API keys: the hash protects against database disclosure (the stored
// value cannot be replayed as a credential) and the comparison is constant time.
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
// An empty presented secret is rejected before hashing: a client that sends no
// client_secret at all must fail authentication rather than be compared against
// the hash of the empty string, which a misconfigured row could plausibly hold.
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
