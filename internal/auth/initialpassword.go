package auth

import (
	"crypto/rand"
	"encoding/base64"
)

// initialPasswordBytes is the length of the random buffer behind a
// system-generated first password. 24 raw bytes encode to 32 base64url
// characters.
const initialPasswordBytes = 24

// GenerateInitialPassword returns a random password for an account being
// provisioned on someone's behalf (the console's POST /admin/users and alumni
// request approval), so "generate a credential" has one implementation rather
// than a weaker invisible duplicate.
//
// base64url needs no URL escaping. The plaintext is returned once and never
// persisted: the caller stores only the hash.
func GenerateInitialPassword() (string, error) {
	buffer := make([]byte, initialPasswordBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
