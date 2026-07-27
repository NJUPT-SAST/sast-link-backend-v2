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
)

const (
	// #nosec G101 -- version marker, not a credential.
	passwordHashVersion    = "pbkdf2-sha512-v1"
	passwordHashIterations = 600_000
	passwordSaltBytes      = 16
	passwordKeyBytes       = 64
)

// PasswordHasher hashes and verifies passwords using PBKDF2-SHA512.
//
// PBKDF2 at 600k iterations is deliberately CPU-heavy; a burst of concurrent
// hashing (login storm, registration burst) can saturate every core and stall
// unrelated requests. Semaphore is an optional weighted gate — when set, each
// hash/verify acquires a slot and releases it when done, capping how many
// derivations run at once. Nil means unbounded, matching previous behavior.
//
// Bounding concurrency converts CPU pressure into a queue, so the wait must be
// abandonable: a single derivation costs ~380ms, meaning a backlog of N requests
// makes the tail wait 380ms*N/slots. Nothing else caps that queue — the HTTP
// server sets no WriteTimeout and login rate limiting is per-IP — so the methods
// take a context and stop waiting once the caller goes away.
type PasswordHasher struct {
	Random    RandomSource
	Semaphore chan struct{}
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

// HashPassword returns a versioned PBKDF2-SHA512 password hash. It returns
// ctx.Err() if the caller is cancelled while queued for a derivation slot.
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
	key, err := pbkdf2.Key(sha512.New, password, salt, passwordHashIterations, passwordKeyBytes)
	if err != nil {
		return "", fmt.Errorf("derive password hash: %w", err)
	}
	return strings.Join([]string{
		passwordHashVersion,
		strconv.Itoa(passwordHashIterations),
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(key),
	}, "$"), nil
}

// VerifyPassword verifies a password against a versioned hash in constant time.
// It returns ctx.Err() if the caller is cancelled while queued for a slot; note
// that this is distinguishable from a wrong password, so callers must not treat
// a context error as an authentication failure.
func (h PasswordHasher) VerifyPassword(ctx context.Context, password, encodedHash string) error {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 4 {
		return ErrInvalidInput
	}
	if parts[0] != passwordHashVersion {
		return ErrUnsupportedVersion
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations != passwordHashIterations {
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
