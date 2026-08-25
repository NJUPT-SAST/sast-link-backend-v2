// Package alumniredis adapts Redis primitives to the alumni-request service
// ports.
package alumniredis

import (
	"context"

	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/alumnirequest"
)

// EndpointLimiter adapts the fixed-window limiter to the alumni-request service
// port.
//
// A per-service adapter rather than a shared one, matching oauthredis and
// sessionredis: each service declares its own LimitResult so it can decide what
// the limiter's outcome means to it, and none of them import another's types.
type EndpointLimiter struct {
	Limiter internalredis.FixedWindowLimiter
}

// Allow reports the rate-limit decision for one endpoint and subject.
func (l EndpointLimiter) Allow(
	ctx context.Context,
	endpoint, subject string,
) (alumnirequest.LimitResult, error) {
	result, err := l.Limiter.Allow(ctx, endpoint, subject)
	if err != nil {
		return alumnirequest.LimitResult{}, err
	}
	return alumnirequest.LimitResult{Allowed: result.Allowed, TTL: result.RetryAfter}, nil
}
