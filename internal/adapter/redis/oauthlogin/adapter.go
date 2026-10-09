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
	"fmt"
	"strconv"
	"strings"
	"time"

	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauthlogin"
)

// EndpointLimiter adapts the fixed-window limiter to the oauthlogin service
// port. Unlike the stores in this package it is fail-open: the service logs a
// limiter outage and proceeds, per PRD §6.0.
type EndpointLimiter struct {
	Limiter internalredis.FixedWindowLimiter
}

// Allow reports the rate-limit decision for one endpoint and subject.
func (l EndpointLimiter) Allow(ctx context.Context, endpoint, subject string) (oauthlogin.LimitResult, error) {
	result, err := l.Limiter.Allow(ctx, endpoint, subject)
	if err != nil {
		return oauthlogin.LimitResult{}, err
	}
	return oauthlogin.LimitResult{Allowed: result.Allowed, RetryAfter: result.RetryAfter}, nil
}

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

// SaveLoginCode stashes the user this code redeems to, bound to its PKCE
// challenge.
//
// The value is `userID:challenge` as a raw string rather than JSON: the user ID
// in JSON would unmarshal into `any` as a float64 and silently lose precision
// above 2^53, the challenge is base64url (no colons), so the two halves
// round-trip exactly without paying for encoding. The separator cannot appear
// in either half, making the split unambiguous.
func (s LoginCodeStore) SaveLoginCode(
	ctx context.Context,
	code string,
	userID int64,
	challenge string,
	ttl time.Duration,
) error {
	return s.Store.SetRawOneTime(ctx, s.Store.Keys.LoginCode(code),
		strconv.FormatInt(userID, 10)+":"+challenge, ttl)
}

// ConsumeLoginCode atomically reads and deletes the code, returning the user it
// belonged to and the PKCE challenge it was bound to.
//
// GetDel is what enforces single use: two concurrent exchanges of one code race
// here and exactly one gets a session — and the burn happens before the caller
// verifies its verifier, so a failed verification cannot be retried.
func (s LoginCodeStore) ConsumeLoginCode(ctx context.Context, code string) (int64, string, bool, error) {
	raw, err := s.Store.GetDelRawOneTime(ctx, s.Store.Keys.LoginCode(code))
	if err != nil {
		if errors.Is(err, internalredis.ErrMiss) {
			return 0, "", false, nil
		}
		return 0, "", false, err
	}
	userPart, challenge, separated := strings.Cut(raw, ":")
	userID, parseErr := strconv.ParseInt(userPart, 10, 64)
	if parseErr != nil || !separated {
		// The key existed but held neither shape this writer produces — an
		// unbound code from a pre-PKCE deployment mid-rollout or a corrupted
		// value. Reporting it as not-found would tell the user their code
		// expired; an unbound code must not redeem, and a corrupted one must be
		// visible, so both surface as errors.
		if separated {
			return 0, "", false, parseErr
		}
		return 0, "", false, fmt.Errorf("login code %q: unbound pre-PKCE value", code[:min(len(code), 8)])
	}
	return userID, challenge, true, nil
}
