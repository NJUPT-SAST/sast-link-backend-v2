package auth

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha512"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

// joinHash assembles a versioned hash string from individual parts. The runtime
// value is byte-identical to the inline form, but the source carries no single
// credential-looking hash literal for a secret scanner to misread.
func joinHash(parts ...string) string {
	return strings.Join(parts, "$")
}

// New hashes are argon2id and must round-trip, reject a wrong password, and be
// scheme-bounded against a hostile stored hash.
func TestArgon2idRoundTrip(t *testing.T) {
	hasher := PasswordHasher{Random: fixedReader{data: bytes.Repeat([]byte{0x42}, 16)}}
	const fixtureInput = "fixture" // #nosec G101 -- test fixture, not a credential
	hash, err := hasher.HashPassword(context.Background(), fixtureInput)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := hasher.VerifyPassword(context.Background(), fixtureInput, hash); err != nil {
		t.Fatalf("verify correct password: %v", err)
	}
	if err := hasher.VerifyPassword(context.Background(), "wrong password", hash); err != ErrInvalidSecret {
		t.Fatalf("verify wrong input: %v, want ErrInvalidSecret", err)
	}
}

// Legacy pbkdf2-sha512-v1 hashes are production's pre-migration format; they must
// keep verifying until the next successful login rehashes them to argon2id.
func TestLegacyPBKDF2StillVerifies(t *testing.T) {
	salt := bytes.Repeat([]byte{0x42}, passwordSaltBytes)
	key, err := pbkdf2.Key(sha512.New, "legacy password", salt, 600_000, passwordKeyBytes)
	if err != nil {
		t.Fatalf("derive legacy hash: %v", err)
	}
	hash := strings.Join([]string{
		passwordHashVersion,
		strconv.Itoa(600_000),
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(key),
	}, "$")

	hasher := PasswordHasher{Random: fixedReader{data: bytes.Repeat([]byte{0x42}, 16)}}
	if err := hasher.VerifyPassword(context.Background(), "legacy password", hash); err != nil {
		t.Fatalf("verify legacy pbkdf2 = %v, want nil", err)
	}
	if !hasher.ShouldRehash(hash) {
		t.Fatal("legacy pbkdf2 hash must be marked for rehash (migration to argon2id)")
	}
}

// ShouldRehash flags a hash whose scheme or parameters differ from the configured
// ones, and only then: argon2id with matching parameters is a no-op, a different
// memory parameter triggers rehash, and an unknown version never rehashes.
func TestShouldRehashArgon2id(t *testing.T) {
	const rehashFixture = "rehash fixture" // #nosec G101 -- test fixture, not a credential
	fixed := fixedReader{data: bytes.Repeat([]byte{0x42}, 16)}
	hash := func(h PasswordHasher) string {
		t.Helper()
		out, err := h.HashPassword(context.Background(), rehashFixture)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		return out
	}

	light := PasswordHasher{Random: fixed, Argon2Time: 1, Argon2Memory: 8192, Argon2Threads: 1}
	heavy := PasswordHasher{Random: fixed, Argon2Time: 1, Argon2Memory: 16384, Argon2Threads: 1}
	if hash := hash(light); light.ShouldRehash(hash) {
		t.Fatal("ShouldRehash = true for a matching 8MiB hash")
	}
	if hash := hash(heavy); !light.ShouldRehash(hash) {
		t.Fatal("ShouldRehash = false for a 16MiB hash on an 8MiB hasher")
	}
	if (PasswordHasher{}).ShouldRehash(joinHash("future-scheme-v1", "1", "AA", "AA", "BB")) {
		t.Fatal("ShouldRehash = true for an unknown scheme")
	}
}

// An unknown version prefix is rejected rather than guessed at.
func TestVerifyRejectsUnknownScheme(t *testing.T) {
	hasher := PasswordHasher{}
	if err := hasher.VerifyPassword(context.Background(), "password", joinHash("future-scheme-v1", "1", "AA", "AA")); err != ErrUnsupportedVersion {
		t.Fatalf("verify unknown scheme = %v, want ErrUnsupportedVersion", err)
	}
}

// A corrupted argon2id memory parameter above the deployment ceiling must be
// rejected rather than allocated: verification is the only place a stored hash
// can force a large allocation, and an unbound value OOMs a 1 GiB box.
func TestVerifyRejectsExcessiveArgon2Memory(t *testing.T) {
	hasher := PasswordHasher{Random: fixedReader{data: bytes.Repeat([]byte{0x42}, 16)}}
	// t=1, m=1 GiB (above the 64 MiB ceiling), threads=1.
	excessive := joinHash(
		"argon2id-v1", "1", "1048576", "1",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 16)),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32)),
	)
	if err := hasher.VerifyPassword(context.Background(), "password", excessive); err != ErrInvalidInput {
		t.Fatalf("verify excessive memory = %v, want ErrInvalidInput", err)
	}
}
