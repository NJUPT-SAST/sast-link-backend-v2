package sessionadapter

import (
	"context"
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

func (s BlacklistStore) IsJTIBlacklisted(ctx context.Context, jti string) (bool, error) {
	return s.Store.IsJTIBlacklisted(ctx, jti)
}
