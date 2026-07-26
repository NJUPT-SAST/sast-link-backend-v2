package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Cmdable is the minimal Redis command surface used by auth infrastructure.
type Cmdable interface {
	SetNX(context.Context, string, any, time.Duration) *goredis.BoolCmd
	GetDel(context.Context, string) *goredis.StringCmd
	Set(context.Context, string, any, time.Duration) *goredis.StatusCmd
	Get(context.Context, string) *goredis.StringCmd
	Del(context.Context, ...string) *goredis.IntCmd
	PTTL(context.Context, string) *goredis.DurationCmd
	Eval(context.Context, string, []string, ...any) *goredis.Cmd
}

var (
	// ErrMiss reports a missing or already consumed Redis value.
	ErrMiss = errors.New("redis: key not found")
	// ErrAlreadyExists reports an existing one-time value.
	ErrAlreadyExists = errors.New("redis: key already exists")
	// ErrInvalidArgument reports invalid Redis state input.
	ErrInvalidArgument = errors.New("redis: invalid argument")
)

// Keys builds namespaced Redis keys for authentication state.
type Keys struct {
	Prefix string
}

// NewKeys returns a key builder with a normalized prefix.
func NewKeys(prefix string) Keys {
	return Keys{Prefix: strings.Trim(prefix, ":")}
}

func (k Keys) join(parts ...string) string {
	filtered := make([]string, 0, len(parts)+1)
	if k.Prefix != "" {
		filtered = append(filtered, k.Prefix)
	}
	filtered = append(filtered, parts...)
	return strings.Join(filtered, ":")
}

func dynamicKeySegment(value string) string {
	if value == "" {
		return "%00"
	}
	value = strings.ReplaceAll(value, "%", "%25")
	return strings.ReplaceAll(value, ":", "%3A")
}

// OneTime returns a key for one-time OAuth/auth payloads.
func (k Keys) OneTime(kind, id string) string {
	return k.join(dynamicKeySegment(kind), dynamicKeySegment(id))
}

// VerifyCode returns a verification-code key.
func (k Keys) VerifyCode(email string) string { return k.join("verify", dynamicKeySegment(email)) }

// OAuthState returns an OAuth state key.
func (k Keys) OAuthState(state string) string {
	return k.join("oauth", "state", dynamicKeySegment(state))
}

// OAuthRegistration returns an OAuth registration-state key.
func (k Keys) OAuthRegistration(state string) string {
	return k.join("oauth", "registration", dynamicKeySegment(state))
}

// RegisterTicket returns a registration-ticket key.
func (k Keys) RegisterTicket(ticket string) string {
	return k.join("auth", "register_ticket", dynamicKeySegment(ticket))
}

// BindTicket returns a binding-ticket key.
func (k Keys) BindTicket(ticket string) string {
	return k.join("auth", "bind_ticket", dynamicKeySegment(ticket))
}

// LoginCode returns an OAuth login-code key.
func (k Keys) LoginCode(code string) string {
	return k.join("auth", "login_code", dynamicKeySegment(code))
}

// JTIBlacklist returns a JWT blacklist key.
func (k Keys) JTIBlacklist(jti string) string {
	return k.join("token", "blacklist", dynamicKeySegment(jti))
}

// RateLimit returns a fixed-window rate-limiter key.
func (k Keys) RateLimit(scope, id string) string {
	return k.join("ratelimit", dynamicKeySegment(id), dynamicKeySegment(scope))
}

// LoginFailure returns a password-login failure counter key.
func (k Keys) LoginFailure(email string) string {
	return k.join("auth", "login_failure", dynamicKeySegment(email))
}

// Store provides typed Redis auth helpers.
type Store struct {
	Client Cmdable
	Keys   Keys
}

// SetOneTime stores a JSON payload using SET NX EX semantics.
func (s Store) SetOneTime(ctx context.Context, key string, payload any, ttl time.Duration) error {
	if s.Client == nil || key == "" || payload == nil || ttl <= 0 {
		return fmt.Errorf("set one-time: %w", ErrInvalidArgument)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal one-time payload: %w", err)
	}
	ok, err := s.Client.SetNX(ctx, key, encoded, ttl).Result()
	if err != nil {
		return fmt.Errorf("set one-time: %w", err)
	}
	if !ok {
		return ErrAlreadyExists
	}
	return nil
}

// GetDelOneTime atomically consumes a JSON payload.
func (s Store) GetDelOneTime(ctx context.Context, key string, target any) error {
	if s.Client == nil || key == "" || target == nil {
		return fmt.Errorf("getdel one-time: %w", ErrInvalidArgument)
	}
	value, err := s.Client.GetDel(ctx, key).Result()
	if errors.Is(err, goredis.Nil) {
		return ErrMiss
	}
	if err != nil {
		return fmt.Errorf("getdel one-time: %w", err)
	}
	if err := json.Unmarshal([]byte(value), target); err != nil {
		return fmt.Errorf("unmarshal one-time payload: %w", err)
	}
	return nil
}

// BlacklistJTI blacklists a JWT ID until its token expiry.
func (s Store) BlacklistJTI(ctx context.Context, jti string, ttl time.Duration) error {
	if s.Client == nil || jti == "" || ttl <= 0 {
		return fmt.Errorf("blacklist jti: %w", ErrInvalidArgument)
	}
	if err := s.Client.Set(ctx, s.Keys.JTIBlacklist(jti), "1", ttl).Err(); err != nil {
		return fmt.Errorf("blacklist jti: %w", err)
	}
	return nil
}

// IsJTIBlacklisted reports whether a JWT ID is blacklisted.
func (s Store) IsJTIBlacklisted(ctx context.Context, jti string) (bool, error) {
	if s.Client == nil || jti == "" {
		return false, fmt.Errorf("get jti blacklist: %w", ErrInvalidArgument)
	}
	_, err := s.Client.Get(ctx, s.Keys.JTIBlacklist(jti)).Result()
	if errors.Is(err, goredis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get jti blacklist: %w", err)
	}
	return true, nil
}

// LoginFailureState is a fixed-window password-login failure counter snapshot.
type LoginFailureState struct {
	Count int
	TTL   time.Duration
}

const loginFailureCounterScript = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return {current, redis.call("PTTL", KEYS[1])}
`

// GetLoginFailures reads the current password-login failure counter without mutating it.
func (s Store) GetLoginFailures(ctx context.Context, email string) (LoginFailureState, error) {
	if s.Client == nil || email == "" {
		return LoginFailureState{}, fmt.Errorf("get login failures: %w", ErrInvalidArgument)
	}
	key := s.Keys.LoginFailure(email)
	count, err := s.Client.Get(ctx, key).Int()
	if errors.Is(err, goredis.Nil) {
		return LoginFailureState{}, nil
	}
	if err != nil {
		return LoginFailureState{}, fmt.Errorf("get login failures: %w", err)
	}
	ttl, err := s.Client.PTTL(ctx, key).Result()
	if err != nil {
		return LoginFailureState{}, fmt.Errorf("get login failures ttl: %w", err)
	}
	if ttl < 0 {
		ttl = 0
	}
	return LoginFailureState{Count: count, TTL: ttl}, nil
}

// RecordLoginFailure increments the password-login failure counter in a fixed window.
func (s Store) RecordLoginFailure(ctx context.Context, email string, window time.Duration) (LoginFailureState, error) {
	if s.Client == nil || email == "" || window <= 0 {
		return LoginFailureState{}, fmt.Errorf("record login failure: %w", ErrInvalidArgument)
	}
	windowMilliseconds := window.Milliseconds()
	if windowMilliseconds <= 0 {
		return LoginFailureState{}, fmt.Errorf("record login failure: %w", ErrInvalidArgument)
	}
	values, err := s.Client.Eval(ctx, loginFailureCounterScript, []string{s.Keys.LoginFailure(email)}, int(windowMilliseconds)).Slice()
	if err != nil {
		return LoginFailureState{}, fmt.Errorf("record login failure eval: %w", err)
	}
	if len(values) != 2 {
		return LoginFailureState{}, fmt.Errorf("record login failure eval: unexpected result")
	}
	count, err := redisInt(values[0])
	if err != nil {
		return LoginFailureState{}, err
	}
	ttlMilliseconds, err := redisInt(values[1])
	if err != nil {
		return LoginFailureState{}, err
	}
	if ttlMilliseconds < 0 {
		ttlMilliseconds = 0
	}
	return LoginFailureState{Count: count, TTL: time.Duration(ttlMilliseconds) * time.Millisecond}, nil
}

// ResetLoginFailures clears the password-login failure counter.
func (s Store) ResetLoginFailures(ctx context.Context, email string) error {
	if s.Client == nil || email == "" {
		return fmt.Errorf("reset login failures: %w", ErrInvalidArgument)
	}
	if err := s.Client.Del(ctx, s.Keys.LoginFailure(email)).Err(); err != nil {
		return fmt.Errorf("reset login failures: %w", err)
	}
	return nil
}
