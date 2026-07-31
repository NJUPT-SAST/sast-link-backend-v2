// Package oauthloginredis adapts Redis primitives to the third-party OAuth login
// service ports.
//
// All three stores here are fail-closed (PRD §6.0): Redis holds the only copy of
// an OAuth state, a parked registration, and a login code, so an unreadable
// value cannot be treated as valid. Each adapter reports a missing key as
// not-found and a Redis failure as an error, leaving the service to reject the
// request rather than let it through.
package oauthloginredis

import (
	"context"
	"errors"
	"strconv"
	"time"

	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauthlogin"
)

// StateStore persists the CSRF state for one authorization round trip.
type StateStore struct {
	Store internalredis.Store
}

// SaveOAuthState stashes the state payload.
//
// SetOneTime's SET NX semantics refuse to overwrite a live key. States are 256
// random bits, so a collision is either a repeat of an in-flight state or an
// attempt to retarget somebody else's pending login; refusing keeps one state
// bound to one provider and redirect.
func (s StateStore) SaveOAuthState(
	ctx context.Context,
	state string,
	payload oauthlogin.StatePayload,
	ttl time.Duration,
) error {
	return s.Store.SetOneTime(ctx, s.Store.Keys.OAuthState(state), payload, ttl)
}

// ConsumeOAuthState atomically reads and deletes the state.
//
// GetDel is what makes one authorization round trip usable once: a replayed
// callback finds nothing. A missing key is an ordinary outcome — expired,
// forged, or already spent — and is reported as not-found so the service can ask
// the user to restart instead of returning a server error.
func (s StateStore) ConsumeOAuthState(
	ctx context.Context,
	state string,
) (oauthlogin.StatePayload, bool, error) {
	var payload oauthlogin.StatePayload
	err := s.Store.GetDelOneTime(ctx, s.Store.Keys.OAuthState(state), &payload)
	if err != nil {
		if errors.Is(err, internalredis.ErrMiss) {
			return oauthlogin.StatePayload{}, false, nil
		}
		return oauthlogin.StatePayload{}, false, err
	}
	return payload, true, nil
}

// RegistrationStateStore parks a third-party identity for a user who has no
// account yet.
type RegistrationStateStore struct {
	Store internalredis.Store
}

// SaveRegistrationState stashes the parked identity.
func (s RegistrationStateStore) SaveRegistrationState(
	ctx context.Context,
	state string,
	payload oauthlogin.RegistrationPayload,
	ttl time.Duration,
) error {
	return s.Store.SetOneTime(ctx, s.Store.Keys.OAuthRegistration(state), payload, ttl)
}

// ConsumeRegistrationState atomically reads and deletes the parked identity.
//
// The value is consumed before the caller compares its stored oauth_state
// against the submitted one, so a mismatched pair is spent rather than
// retryable. That is deliberate: the pair was presented and failed the double
// binding, and leaving it alive would let an attacker holding a leaked
// registration_state keep guessing the state it was issued with.
func (s RegistrationStateStore) ConsumeRegistrationState(
	ctx context.Context,
	state string,
) (oauthlogin.RegistrationPayload, bool, error) {
	var payload oauthlogin.RegistrationPayload
	err := s.Store.GetDelOneTime(ctx, s.Store.Keys.OAuthRegistration(state), &payload)
	if err != nil {
		if errors.Is(err, internalredis.ErrMiss) {
			return oauthlogin.RegistrationPayload{}, false, nil
		}
		return oauthlogin.RegistrationPayload{}, false, err
	}
	return payload, true, nil
}

// LoginCodeStore holds the one-time code the callback hands to the frontend.
type LoginCodeStore struct {
	Store internalredis.Store
}

// SaveLoginCode stashes the user this code redeems to.
//
// The user ID is stored as a decimal string rather than a JSON number: JSON
// unmarshalling into `any` would yield a float64 and silently lose precision
// above 2^53, and a string round-trips exactly.
func (s LoginCodeStore) SaveLoginCode(
	ctx context.Context,
	code string,
	userID int64,
	ttl time.Duration,
) error {
	return s.Store.SetOneTime(ctx, s.Store.Keys.LoginCode(code),
		strconv.FormatInt(userID, 10), ttl)
}

// ConsumeLoginCode atomically reads and deletes the code, returning the user it
// belonged to.
//
// GetDel is what enforces single use: two concurrent exchanges of one code race
// here and exactly one gets a session.
func (s LoginCodeStore) ConsumeLoginCode(ctx context.Context, code string) (int64, bool, error) {
	var raw string
	err := s.Store.GetDelOneTime(ctx, s.Store.Keys.LoginCode(code), &raw)
	if err != nil {
		if errors.Is(err, internalredis.ErrMiss) {
			return 0, false, nil
		}
		return 0, false, err
	}
	userID, parseErr := strconv.ParseInt(raw, 10, 64)
	if parseErr != nil {
		// The key existed but did not hold a user ID. Treating it as not-found
		// would tell the user their code expired; this is a corrupted value and
		// must surface as an error so it is visible.
		return 0, false, parseErr
	}
	return userID, true, nil
}
