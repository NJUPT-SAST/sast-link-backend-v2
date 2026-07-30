package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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
	Pipeline() goredis.Pipeliner
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

// VerifyCode returns a verification-code key scoped by purpose so codes issued
// for one flow (register / reset_password / bind_email) cannot be consumed by another.
func (k Keys) VerifyCode(purpose, email string) string {
	return k.join("verify", dynamicKeySegment(purpose), dynamicKeySegment(email))
}

// OAuthState returns an OAuth state key.
func (k Keys) OAuthState(state string) string {
	return k.join("oauth", "state", dynamicKeySegment(state))
}

// OAuthRegistration returns an OAuth registration-state key.
func (k Keys) OAuthRegistration(state string) string {
	return k.join("oauth", "registration", dynamicKeySegment(state))
}

// AuthorizeRequest returns the key holding a validated but unconfirmed
// /oauth/authorize request, pending the user's consent decision.
func (k Keys) AuthorizeRequest(requestID string) string {
	return k.join("oauth", "authorize_request", dynamicKeySegment(requestID))
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

// PeekOneTime reads a one-time JSON payload without consuming it, for flows that
// must validate further input before spending the token.
func (s Store) PeekOneTime(ctx context.Context, key string, target any) error {
	if s.Client == nil || key == "" || target == nil {
		return fmt.Errorf("peek one-time: %w", ErrInvalidArgument)
	}
	value, err := s.Client.Get(ctx, key).Result()
	if errors.Is(err, goredis.Nil) {
		return ErrMiss
	}
	if err != nil {
		return fmt.Errorf("peek one-time: %w", err)
	}
	if err := json.Unmarshal([]byte(value), target); err != nil {
		return fmt.Errorf("unmarshal one-time payload: %w", err)
	}
	return nil
}

// DeleteOneTime removes a one-time key and reports whether this call was the one
// that deleted it. Concurrent callers can use that to elect a single winner.
func (s Store) DeleteOneTime(ctx context.Context, key string) (bool, error) {
	if s.Client == nil || key == "" {
		return false, fmt.Errorf("delete one-time: %w", ErrInvalidArgument)
	}
	deleted, err := s.Client.Del(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("delete one-time: %w", err)
	}
	return deleted > 0, nil
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

// SaveVerificationCode stores a numeric verification code for the given purpose
// and email, resetting the failed-attempt counter so a freshly issued code
// always starts with a full attempt budget. Without the reset, exhausted
// attempts from a previous code would kill the new one on its first use.
func (s Store) SaveVerificationCode(ctx context.Context, purpose, email, code string, ttl time.Duration) error {
	if s.Client == nil || purpose == "" || email == "" || code == "" || ttl <= 0 {
		return fmt.Errorf("save verification code: %w", ErrInvalidArgument)
	}
	milliseconds := ttl.Milliseconds()
	if milliseconds <= 0 || milliseconds > math.MaxInt {
		return fmt.Errorf("save verification code: %w", ErrInvalidArgument)
	}
	keys := []string{
		s.Keys.VerifyCode(purpose, email),
		s.Keys.VerificationCodeAttempt(purpose, email),
	}
	if err := s.Client.Eval(ctx, saveVerificationCodeScript, keys, code, int(milliseconds)).Err(); err != nil {
		return fmt.Errorf("save verification code: %w", err)
	}
	return nil
}

// saveVerificationCodeScript writes the code and clears the attempt counter in
// one step, so a new code can never inherit a spent attempt budget.
const saveVerificationCodeScript = `
redis.call("SET", KEYS[1], ARGV[1], "PX", tonumber(ARGV[2]))
redis.call("DEL", KEYS[2])
return 1
`

// verificationCodeAttemptScript compares a submitted code against the stored one
// and deletes the key only on a match or once the attempt budget is spent.
//
// A plain GETDEL would let one wrong guess burn the valid code (a trivial denial
// of service against any known address), while never deleting on mismatch would
// turn a 6-digit code into an unlimited brute-force target. Bounding the
// attempts keeps a typo recoverable and caps the guess space at ARGV[2]/10^6.
//
// The attempt counter shares the code's remaining TTL, so it cannot outlive the
// code or be reset by re-submitting.
//
// Returns {status, attempts_remaining}: 0 = missing/exhausted, 1 = match,
// 2 = mismatch with attempts left.
const verificationCodeAttemptScript = `
local stored = redis.call("GET", KEYS[1])
if not stored then
  redis.call("DEL", KEYS[2])
  return {0, 0}
end
if stored == ARGV[1] then
  redis.call("DEL", KEYS[1], KEYS[2])
  return {1, 0}
end
local attempts = redis.call("INCR", KEYS[2])
local limit = tonumber(ARGV[2])
if attempts == 1 then
  local ttl = redis.call("PTTL", KEYS[1])
  if ttl > 0 then
    redis.call("PEXPIRE", KEYS[2], ttl)
  end
end
if attempts >= limit then
  redis.call("DEL", KEYS[1], KEYS[2])
  return {0, 0}
end
return {2, limit - attempts}
`

// maximumVerificationCodeAttempts bounds guesses per issued code. Five leaves
// room for typos while capping the brute-force success rate at 5-in-a-million.
const maximumVerificationCodeAttempts = 5

// VerificationCodeAttempt returns the key holding the failed-attempt counter for
// an issued verification code.
func (k Keys) VerificationCodeAttempt(purpose, email string) string {
	return k.join("verify", "attempt", dynamicKeySegment(purpose), dynamicKeySegment(email))
}

// VerifyVerificationCode atomically compares code against the stored value. The
// code survives a wrong guess until the attempt budget is exhausted, so a typo
// does not force the user to request a new one. It reports whether the code
// matched and, on mismatch, how many attempts remain.
func (s Store) VerifyVerificationCode(ctx context.Context, purpose, email, code string) (bool, int, error) {
	if s.Client == nil || purpose == "" || email == "" || code == "" {
		return false, 0, fmt.Errorf("verify verification code: %w", ErrInvalidArgument)
	}
	keys := []string{
		s.Keys.VerifyCode(purpose, email),
		s.Keys.VerificationCodeAttempt(purpose, email),
	}
	values, err := s.Client.Eval(ctx, verificationCodeAttemptScript, keys, code, maximumVerificationCodeAttempts).Slice()
	if err != nil {
		return false, 0, fmt.Errorf("verify verification code eval: %w", err)
	}
	if len(values) != 2 {
		return false, 0, fmt.Errorf("verify verification code eval: unexpected result")
	}
	status, err := redisInt(values[0])
	if err != nil {
		return false, 0, err
	}
	remaining, err := redisInt(values[1])
	if err != nil {
		return false, 0, err
	}
	return status == 1, remaining, nil
}

// DiscardVerificationCode drops a verified code and its attempt counter. Used
// when a later step in the same flow fails after the code already matched, so a
// retry cannot reuse it.
func (s Store) DiscardVerificationCode(ctx context.Context, purpose, email string) error {
	if s.Client == nil || purpose == "" || email == "" {
		return fmt.Errorf("discard verification code: %w", ErrInvalidArgument)
	}
	keys := []string{
		s.Keys.VerifyCode(purpose, email),
		s.Keys.VerificationCodeAttempt(purpose, email),
	}
	if err := s.Client.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("discard verification code: %w", err)
	}
	return nil
}

// SaveRegisterTicket stores a one-time ticket bound to the verified email.
func (s Store) SaveRegisterTicket(ctx context.Context, ticket, email string, ttl time.Duration) error {
	if s.Client == nil || ticket == "" || email == "" || ttl <= 0 {
		return fmt.Errorf("save register ticket: %w", ErrInvalidArgument)
	}
	return s.SetOneTime(ctx, s.Keys.RegisterTicket(ticket), email, ttl)
}

// PeekRegisterTicket reads the email bound to a ticket without consuming it.
func (s Store) PeekRegisterTicket(ctx context.Context, ticket string) (string, bool, error) {
	if s.Client == nil || ticket == "" {
		return "", false, fmt.Errorf("peek register ticket: %w", ErrInvalidArgument)
	}
	var email string
	if err := s.PeekOneTime(ctx, s.Keys.RegisterTicket(ticket), &email); err != nil {
		if errors.Is(err, ErrMiss) {
			return "", false, nil
		}
		return "", false, err
	}
	return email, true, nil
}

// ConsumeRegisterTicket deletes a register ticket.
func (s Store) ConsumeRegisterTicket(ctx context.Context, ticket string) error {
	if s.Client == nil || ticket == "" {
		return fmt.Errorf("consume register ticket: %w", ErrInvalidArgument)
	}
	if _, err := s.DeleteOneTime(ctx, s.Keys.RegisterTicket(ticket)); err != nil {
		return err
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

// BlacklistJTIBatch blacklists multiple JTIs in one MSET round trip. Password
// change/reset revokes every live session of a user, so delivering each JTI
// with its own SET costs one Redis RTT per device — MSET keeps it constant.
// Every entry in the batch must already be validated (non-empty JTI, positive
// TTL); empty batches are a no-op.
func (s Store) BlacklistJTIBatch(ctx context.Context, entries map[string]time.Duration) error {
	if s.Client == nil {
		return fmt.Errorf("blacklist jti batch: %w", ErrInvalidArgument)
	}
	if len(entries) == 0 {
		return nil
	}
	// MSET cannot carry per-key TTLs, so write each key with its expiry through
	// a pipelined SET — still one network round trip for the whole batch.
	pipe := s.Client.Pipeline()
	for jti, ttl := range entries {
		if jti == "" || ttl <= 0 {
			continue
		}
		pipe.Set(ctx, s.Keys.JTIBlacklist(jti), "1", ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("blacklist jti batch: %w", err)
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
