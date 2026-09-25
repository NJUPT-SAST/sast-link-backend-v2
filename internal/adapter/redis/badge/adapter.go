// Package badgeredis adapts Redis primitives to the badge service ports.
package badgeredis

import (
	"context"

	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/badge"
)

// EndpointLimiter adapts the shared fixed-window limiter to the badge service's
// per-user toggle cap.
type EndpointLimiter struct {
	Limiter internalredis.FixedWindowLimiter
}

func (l EndpointLimiter) Allow(ctx context.Context, endpoint, subject string) (badge.LimitResult, error) {
	result, err := l.Limiter.Allow(ctx, endpoint, subject)
	if err != nil {
		return badge.LimitResult{}, err
	}
	return badge.LimitResult{Allowed: result.Allowed, RetryAfter: result.RetryAfter}, nil
}
