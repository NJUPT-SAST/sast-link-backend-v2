// Package sessionredis adapts Redis primitives to the session service ports.
package sessionredis

import (
	"context"
	"errors"
	"time"

	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
)

type EndpointLimiter struct {
	Limiter internalredis.FixedWindowLimiter
}

func (l EndpointLimiter) Allow(ctx context.Context, endpoint, subject string) (session.LimitResult, error) {
	result, err := l.Limiter.Allow(ctx, endpoint, subject)
	if err != nil {
		return session.LimitResult{}, err
	}
	return session.LimitResult{Allowed: result.Allowed, RetryAfter: result.RetryAfter}, nil
}

type LoginFailureStore struct {
	Store  internalredis.Store
	Limit  int
	Window time.Duration
}

func (s LoginFailureStore) IsLocked(ctx context.Context, identifier string) (bool, time.Duration, error) {
	state, err := s.Store.GetLoginFailures(ctx, identifier)
	if err != nil {
		return false, 0, err
	}
	return s.Limit > 0 && state.Count >= s.Limit && state.TTL > 0, state.TTL, nil
}

func (s LoginFailureStore) RecordFailure(ctx context.Context, identifier string) (session.LoginFailureResult, error) {
	raw, err := s.Store.RecordLoginFailure(ctx, identifier, s.Window)
	if err != nil {
		return session.LoginFailureResult{}, err
	}
	return session.LoginFailureResult{
		Count:  raw.Count,
		TTL:    raw.TTL,
		Locked: s.Limit > 0 && raw.Count >= s.Limit && raw.TTL > 0,
	}, nil
}

func (s LoginFailureStore) Reset(ctx context.Context, identifier string) error {
	return s.Store.ResetLoginFailures(ctx, identifier)
}

type BlacklistStore struct {
	Store internalredis.Store
}

func (s BlacklistStore) BlacklistJTI(ctx context.Context, jti string, ttl time.Duration) error {
	return s.Store.BlacklistJTI(ctx, jti, ttl)
}

// BlacklistJTIBatch delivers a whole revoked session set in one round trip.
// Used by password change/reset where every live token of the user is revoked
// at once; the per-token loop would cost one RTT per device.
func (s BlacklistStore) BlacklistJTIBatch(ctx context.Context, entries map[string]time.Duration) error {
	return s.Store.BlacklistJTIBatch(ctx, entries)
}

func (s BlacklistStore) IsJTIBlacklisted(ctx context.Context, jti string) (bool, error) {
	return s.Store.IsJTIBlacklisted(ctx, jti)
}

type BindTicketStore struct {
	Store internalredis.Store
}

func (s BindTicketStore) SaveBindTicket(ctx context.Context, ticket string, payload session.BindTicketPayload, ttl time.Duration) error {
	return s.Store.SetOneTime(ctx, s.Store.Keys.BindTicket(ticket), payload, ttl)
}

func (s BindTicketStore) PeekBindTicket(ctx context.Context, ticket string) (session.BindTicketPayload, bool, error) {
	var payload session.BindTicketPayload
	if err := s.Store.PeekOneTime(ctx, s.Store.Keys.BindTicket(ticket), &payload); err != nil {
		if errors.Is(err, internalredis.ErrMiss) {
			return session.BindTicketPayload{}, false, nil
		}
		return session.BindTicketPayload{}, false, err
	}
	return payload, true, nil
}

func (s BindTicketStore) ConsumeBindTicket(ctx context.Context, ticket string) (bool, error) {
	return s.Store.DeleteOneTime(ctx, s.Store.Keys.BindTicket(ticket))
}

// UnbindCooldownStore adapts the identity-unbind cooldown to the session port.
// Window is the PRD §4.8 cooldown length; a non-positive value disables the
// cooldown, which the service treats as "not configured" rather than "always
// allowed at zero TTL".
type UnbindCooldownStore struct {
	Store  internalredis.Store
	Window time.Duration
}

func (s UnbindCooldownStore) Acquire(ctx context.Context, subject string) (bool, time.Duration, error) {
	if s.Window <= 0 {
		return true, 0, nil
	}
	return s.Store.AcquireUnbindCooldown(ctx, subject, s.Window)
}

func (s UnbindCooldownStore) Release(ctx context.Context, subject string) error {
	if s.Window <= 0 {
		return nil
	}
	return s.Store.ReleaseUnbindCooldown(ctx, subject)
}
