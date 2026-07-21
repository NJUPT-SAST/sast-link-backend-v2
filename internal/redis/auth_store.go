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
	for _, part := range parts {
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	return strings.Join(filtered, ":")
}

// OneTime returns a key for one-time OAuth/auth payloads.
func (k Keys) OneTime(kind, id string) string { return k.join(kind, id) }

// VerifyCode returns a verification-code key.
func (k Keys) VerifyCode(email string) string { return k.join("verify", email) }

// OAuthState returns an OAuth state key.
func (k Keys) OAuthState(state string) string { return k.join("oauth", "state", state) }

// OAuthRegistration returns an OAuth registration-state key.
func (k Keys) OAuthRegistration(state string) string { return k.join("oauth", "registration", state) }

// RegisterTicket returns a registration-ticket key.
func (k Keys) RegisterTicket(ticket string) string { return k.join("auth", "register_ticket", ticket) }

// BindTicket returns a binding-ticket key.
func (k Keys) BindTicket(ticket string) string { return k.join("auth", "bind_ticket", ticket) }

// LoginCode returns an OAuth login-code key.
func (k Keys) LoginCode(code string) string { return k.join("auth", "login_code", code) }

// JTIBlacklist returns a JWT blacklist key.
func (k Keys) JTIBlacklist(jti string) string { return k.join("token", "blacklist", jti) }

// TokenVersion returns a token-version cache key.
func (k Keys) TokenVersion(userID string) string { return k.join("token", "version", userID) }

// RateLimit returns a fixed-window rate-limiter key.
func (k Keys) RateLimit(scope, id string) string { return k.join("ratelimit", id, scope) }

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

// SetTokenVersion caches a user's token_version.
func (s Store) SetTokenVersion(ctx context.Context, userID string, version int, ttl time.Duration) error {
	if s.Client == nil || userID == "" || version < 0 || ttl <= 0 {
		return fmt.Errorf("set token version: %w", ErrInvalidArgument)
	}
	if err := s.Client.Set(ctx, s.Keys.TokenVersion(userID), version, ttl).Err(); err != nil {
		return fmt.Errorf("set token version: %w", err)
	}
	return nil
}

// GetTokenVersion reads a cached token_version.
func (s Store) GetTokenVersion(ctx context.Context, userID string) (int, bool, error) {
	if s.Client == nil || userID == "" {
		return 0, false, fmt.Errorf("get token version: %w", ErrInvalidArgument)
	}
	version, err := s.Client.Get(ctx, s.Keys.TokenVersion(userID)).Int()
	if errors.Is(err, goredis.Nil) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("get token version: %w", err)
	}
	return version, true, nil
}
