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
// provisioned on someone's behalf.
//
// Two flows create accounts whose owner is not present to choose a password: the
// console's POST /admin/users and the approval of an alumni account request.
// Both need the same thing, and a second implementation of "generate a
// credential" is the kind of duplicate where a weaker copy is invisible — the
// output looks equally random either way, and nothing fails until someone
// audits the entropy.
//
// raw base64url so the value needs no URL escaping and is easy to read back over
// a phone call. The plaintext is returned once and never persisted: the caller
// stores only the hash.
func GenerateInitialPassword() (string, error) {
	buffer := make([]byte, initialPasswordBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
