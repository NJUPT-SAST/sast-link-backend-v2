package redis

import (
	"context"
	"fmt"
	"math"
	"time"
)

const fixedWindowLimiterScript = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[2])
end
local ttl = redis.call("PTTL", KEYS[1])
return {current, tonumber(ARGV[1]), ttl}
`

// RateLimitResult describes a fixed-window rate-limit decision.
type RateLimitResult struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter time.Duration
}

// FixedWindowLimiter applies an atomic Lua fixed-window limit.
type FixedWindowLimiter struct {
	Client Cmdable
	Keys   Keys
	Limit  int
	Window time.Duration
}

// Allow increments the subject's current window and reports the decision.
func (l FixedWindowLimiter) Allow(ctx context.Context, scope, subject string) (RateLimitResult, error) {
	if l.Client == nil || scope == "" || subject == "" || l.Limit <= 0 || l.Window < time.Second {
		return RateLimitResult{}, fmt.Errorf("rate limit: %w", ErrInvalidArgument)
	}
	windowMilliseconds := l.Window.Milliseconds()
	if windowMilliseconds <= 0 || windowMilliseconds > math.MaxInt {
		return RateLimitResult{}, fmt.Errorf("rate limit: %w", ErrInvalidArgument)
	}
	values, err := l.Client.Eval(ctx, fixedWindowLimiterScript, []string{l.Keys.RateLimit(scope, subject)}, l.Limit, int(windowMilliseconds)).Slice()
	if err != nil {
		return RateLimitResult{}, fmt.Errorf("rate limit eval: %w", err)
	}
	if len(values) != 3 {
		return RateLimitResult{}, fmt.Errorf("rate limit eval: unexpected result")
	}
	count, err := redisInt(values[0])
	if err != nil {
		return RateLimitResult{}, err
	}
	limit, err := redisInt(values[1])
	if err != nil {
		return RateLimitResult{}, err
	}
	ttl, err := redisInt(values[2])
	if err != nil {
		return RateLimitResult{}, err
	}
	if ttl <= 0 && count > limit {
		ttl = 1
	}
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}
	return RateLimitResult{
		Allowed:    count <= limit,
		Limit:      limit,
		Remaining:  remaining,
		RetryAfter: time.Duration(ttl) * time.Millisecond,
	}, nil
}

func redisInt(value any) (int, error) {
	switch typed := value.(type) {
	case int:
		return typed, nil
	case int64:
		return int(typed), nil
	case uint64:
		if typed > uint64(math.MaxInt) {
			return 0, fmt.Errorf("redis integer: %w", ErrInvalidArgument)
		}
		return int(typed), nil
	default:
		return 0, fmt.Errorf("redis integer: unsupported %T", value)
	}
}
