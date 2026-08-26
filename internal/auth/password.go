package auth

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// #nosec G101 -- version markers, not credentials.
	passwordHashVersion = "pbkdf2-sha512-v1"
	passwordSaltBytes   = 16
	passwordKeyBytes    = 64

	// minimumHashIterations and maximumHashIterations bound the PBKDF2 count
	// accepted from a stored legacy hash, so a corrupted or hostile iterations
	// field cannot turn one login into a CPU-burning DoS. The ceiling still
	// accommodates the historical fixed parameter of 600k.
	minimumHashIterations = 10_000
	maximumHashIterations = 1_000_000

	// memoryHashKeyBytes is the derived-key length for argon2id.
	memoryHashKeyBytes = 32

	// defaultArgon2Time and defaultArgon2Memory (19 MiB, t=2) are the adopted
	// OWASP low-memory work factor.
	defaultArgon2Time    = 2
	defaultArgon2Memory  = 19456
	defaultArgon2Threads = 1

	// Bounds on values read from stored argon2id hashes, keeping verification
	// CPU- and memory-bounded against a corrupted or hostile hash — an unbound
	// memory value lets one hash allocate gigabytes and OOM the process.
	maxArgon2Memory  = 64 * 1024 // KiB == 64 MiB
	maxArgon2Time    = 10
	maxArgon2Threads = 8
)

// PasswordHasher hashes and verifies passwords. New hashes are always argon2id
// with the configured parameters; verification accepts argon2id and the legacy
// pbkdf2-sha512-v1 format so existing accounts keep working until their next
// successful login rehashes them to argon2id (ShouldRehash).
//
// argon2id allocates defaultArgon2Memory per derivation. Semaphore is an
// optional weighted gate capping how many derivations run at once; nil means
// unbounded. A single derivation costs tens to hundreds of ms, so the wait must
// be abandonable: these methods take a context and stop waiting once the caller
// goes away.
type PasswordHasher struct {
	Random    RandomSource
	Semaphore chan struct{}

	// Argon2Time/Memory/Threads are the argon2id parameters for new hashes.
	// Zeros fall back to t=2, m=19456 (19 MiB), p=1.
	Argon2Time, Argon2Memory uint32
	Argon2Threads            uint8
}

// acquire reserves a derivation slot, giving up if ctx is done first. The
// returned release function is a no-op when acquisition failed.
func (h PasswordHasher) acquire(ctx context.Context) (func(), error) {
	if h.Semaphore == nil {
		return func() {}, nil
	}
	// Honour an already-cancelled context even when a slot is free: a select with
	// both cases ready picks at random, which would let abandoned work through.
	if err := ctx.Err(); err != nil {
		return func() {}, err
	}
	select {
	case h.Semaphore <- struct{}{}:
		return func() { <-h.Semaphore }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

// HashPassword returns a versioned argon2id hash. It returns ctx.Err() if the
// caller is cancelled while queued for a derivation slot.
func (h PasswordHasher) HashPassword(ctx context.Context, password string) (string, error) {
	if password == "" {
		return "", ErrInvalidInput
	}
	release, err := h.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()

	salt, err := randomBytes(h.Random, passwordSaltBytes)
	if err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	t := h.Argon2Time
	if t == 0 {
		t = defaultArgon2Time
	}
	m := h.Argon2Memory
	if m == 0 {
		m = defaultArgon2Memory
	}
	threads := h.Argon2Threads
	if threads == 0 {
		threads = defaultArgon2Threads
	}
	key := argon2.IDKey([]byte(password), salt, t, m, threads, memoryHashKeyBytes)
	return strings.Join([]string{
		"argon2id-v1",
		strconv.FormatUint(uint64(t), 10),
		strconv.FormatUint(uint64(m), 10),
		strconv.Itoa(int(threads)),
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(key),
	}, "$"), nil
}

// VerifyPassword verifies a password against a versioned hash in constant time.
// It returns ctx.Err() if the caller is cancelled while queued for a slot; note
// that this is distinguishable from a wrong password, so callers must not treat
// a context error as an authentication failure.
func (h PasswordHasher) VerifyPassword(ctx context.Context, password, encodedHash string) error {
	version, _, _ := strings.Cut(encodedHash, "$")
	switch version {
	case "argon2id-v1":
		return h.verifyArgon2id(ctx, password, encodedHash)
	case passwordHashVersion:
		return h.verifyPBKDF2(ctx, password, encodedHash)
	default:
		return ErrUnsupportedVersion
	}
}

// ShouldRehash reports whether encodedHash was derived with different parameters
// than this hasher is configured for, so a successful verification can upgrade it
// in place (rehash-on-login). A legacy pbkdf2-sha512-v1 hash always rehashes
// (that is the migration off the old scheme); an argon2id hash rehashes when its
// parameters differ from the configured ones. An unparseable hash returns false:
// verification rejects it anyway.
func (h PasswordHasher) ShouldRehash(encodedHash string) bool {
	version, _, _ := strings.Cut(encodedHash, "$")
	if version != "argon2id-v1" {
		// Legacy pbkdf2 or unknown: unknown hashes fail verification and are
		// never rehashed, but every legacy pbkdf2 hash migrates on next login.
		return version == passwordHashVersion
	}
	parts := strings.Split(strings.TrimPrefix(encodedHash, "argon2id-v1$"), "$")
	if len(parts) != 5 {
		return false
	}
	t, e1 := strconv.ParseUint(parts[0], 10, 32)
	m, e2 := strconv.ParseUint(parts[1], 10, 32)
	threads, e3 := strconv.ParseUint(parts[2], 10, 8)
	if e1 != nil || e2 != nil || e3 != nil {
		return false
	}
	wantT, wantM, wantThreads := h.Argon2Time, h.Argon2Memory, h.Argon2Threads
	if wantT == 0 {
		wantT = defaultArgon2Time
	}
	if wantM == 0 {
		wantM = defaultArgon2Memory
	}
	if wantThreads == 0 {
		wantThreads = defaultArgon2Threads
	}
	return uint32(t) != wantT || uint32(m) != wantM || uint8(threads) != wantThreads
}

// verifyPBKDF2 verifies a legacy pbkdf2-sha512-v1 hash until the next successful
// login rehashes it (ShouldRehash returns true). The iteration count is read
// from the stored hash and bounded so a corrupted count cannot turn one login
// into a CPU-burning DoS.
func (h PasswordHasher) verifyPBKDF2(ctx context.Context, password, encodedHash string) error {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 4 {
		return ErrInvalidInput
	}
	if parts[0] != passwordHashVersion {
		return ErrUnsupportedVersion
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < minimumHashIterations || iterations > maximumHashIterations {
		return ErrInvalidInput
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(salt) != passwordSaltBytes {
		return ErrInvalidInput
	}
	expected, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(expected) != passwordKeyBytes {
		return ErrInvalidInput
	}
	release, err := h.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	actual, err := pbkdf2.Key(sha512.New, password, salt, iterations, len(expected))
	if err != nil {
		return fmt.Errorf("derive password verification hash: %w", err)
	}
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return ErrInvalidSecret
	}
	return nil
}

func (h PasswordHasher) verifyArgon2id(ctx context.Context, password, encodedHash string) error {
	payload := strings.TrimPrefix(encodedHash, "argon2id-v1$")
	parts := strings.Split(payload, "$")
	if len(parts) != 5 {
		return ErrInvalidInput
	}
	t, e1 := strconv.ParseUint(parts[0], 10, 32)
	m, e2 := strconv.ParseUint(parts[1], 10, 32)
	threads, e3 := strconv.ParseUint(parts[2], 10, 8)
	if e1 != nil || e2 != nil || e3 != nil ||
		t < 1 || t > maxArgon2Time ||
		m < 8*threads || m > maxArgon2Memory ||
		threads < 1 || threads > maxArgon2Threads {
		return ErrInvalidInput
	}
	salt, e4 := base64.RawURLEncoding.DecodeString(parts[3])
	expected, e5 := base64.RawURLEncoding.DecodeString(parts[4])
	if e4 != nil || e5 != nil || len(salt) != passwordSaltBytes || len(expected) != memoryHashKeyBytes {
		return ErrInvalidInput
	}
	release, err := h.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	actual := argon2.IDKey([]byte(password), salt, uint32(t), uint32(m), uint8(threads), memoryHashKeyBytes)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return ErrInvalidSecret
	}
	return nil
}
