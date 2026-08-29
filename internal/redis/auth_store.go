package redis

import (
	"bytes"
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
	trimmed := strings.Trim(prefix, ":")
	if strings.ContainsAny(trimmed, "{}") {
		// A brace in the prefix would re-scope the {dev} hash tag every device key
		// depends on, scattering one family across cluster slots.
		panic("redis: key prefix must not contain '{' or '}': it breaks the {dev} hash tag")
	}
	return Keys{Prefix: trimmed}
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

// AuthState returns the per-token auth-state cache key. The middleware stores the
// DB-authoritative revocation/role state here under a short TTL, and revocation
// paths write a tombstone so a stale refill cannot re-seed a revoked token's cache.
func (k Keys) AuthState(jti string) string {
	return k.join("auth", "authstate", dynamicKeySegment(jti))
}

// authStateTombstone is written by the revocation paths in place of a delete.
// PutAuthState (SET NX) refuses to overwrite it, closing the stale-refill write
// race, and GetAuthState reads it as a miss so the middleware falls back to the DB.
var authStateTombstone = []byte("__revoked__")

// defaultAuthStateTombstoneTTL is used when Store.AuthStateTombstoneTTL is zero.
// It must outlive the server WriteTimeout so a slow request's stale PUT cannot
// land after the tombstone expires and admit the revoked token.
const defaultAuthStateTombstoneTTL = 15 * time.Second

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
	// AuthStateTombstoneTTL overrides the tombstone lifetime used by
	// DeleteAuthStates; when zero, defaultAuthStateTombstoneTTL is used. The
	// value must exceed the server's WriteTimeout so an in-flight request cannot
	// re-seed the cache after the tombstone expires.
	AuthStateTombstoneTTL time.Duration
}

// GetAuthState reads a cached per-token auth-state blob by JTI. It returns
// found=false for a missing entry; a Redis error propagates so the caller can
// fail open to the database. The value is the raw JSON the middleware wrote.
func (s Store) GetAuthState(ctx context.Context, jti string) ([]byte, bool, error) {
	if s.Client == nil || jti == "" {
		return nil, false, fmt.Errorf("get auth state: %w", ErrInvalidArgument)
	}
	data, err := s.Client.Get(ctx, s.Keys.AuthState(jti)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get auth state: %w", err)
	}
	if bytes.Equal(data, authStateTombstone) {
		// A revocation tombstone reads as a miss so the middleware falls back to
		// the DB (which rejects the revoked token) without a decode-failure log.
		return nil, false, nil
	}
	return data, true, nil
}

// PutAuthState stores a per-token auth-state blob with a TTL. SET NX refuses to
// overwrite a revocation tombstone, so a request that read the DB just before a
// revoking transaction committed cannot re-seed a pre-revocation blob.
func (s Store) PutAuthState(ctx context.Context, jti string, data []byte, ttl time.Duration) error {
	if s.Client == nil || jti == "" || len(data) == 0 || ttl <= 0 {
		return fmt.Errorf("put auth state: %w", ErrInvalidArgument)
	}
	if err := s.Client.SetNX(ctx, s.Keys.AuthState(jti), data, ttl).Err(); err != nil {
		return fmt.Errorf("put auth state: %w", err)
	}
	return nil
}

// DeleteAuthStates writes a short-lived tombstone for a set of JTIs, used by the
// revocation delivery so a revoked token's cache cannot admit it once the DB says
// revoked; PutAuthState's SET NX refuses to overwrite the tombstone, so no stale
// refill can land after a revocation.
func (s Store) tombstoneTTL() time.Duration {
	if s.AuthStateTombstoneTTL > 0 {
		return s.AuthStateTombstoneTTL
	}
	return defaultAuthStateTombstoneTTL
}

func (s Store) DeleteAuthStates(ctx context.Context, jtis []string) error {
	if s.Client == nil {
		return fmt.Errorf("delete auth states: %w", ErrInvalidArgument)
	}
	pipe := s.Client.Pipeline()
	for _, jti := range jtis {
		if jti != "" {
			pipe.Set(ctx, s.Keys.AuthState(jti), authStateTombstone, s.tombstoneTTL())
		}
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("delete auth states: %w", err)
	}
	return nil
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

// SetRawOneTime stores a raw string value under SET NX EX semantics, skipping
// JSON encoding for payloads that are already their final wire form (e.g. a
// decimal user ID).
func (s Store) SetRawOneTime(ctx context.Context, key, value string, ttl time.Duration) error {
	if s.Client == nil || key == "" || value == "" || ttl <= 0 {
		return fmt.Errorf("set raw one-time: %w", ErrInvalidArgument)
	}
	ok, err := s.Client.SetNX(ctx, key, value, ttl).Result()
	if err != nil {
		return fmt.Errorf("set raw one-time: %w", err)
	}
	if !ok {
		return ErrAlreadyExists
	}
	return nil
}

// GetDelRawOneTime atomically consumes a raw string value stored by
// SetRawOneTime.
func (s Store) GetDelRawOneTime(ctx context.Context, key string) (string, error) {
	if s.Client == nil || key == "" {
		return "", fmt.Errorf("getdel raw one-time: %w", ErrInvalidArgument)
	}
	value, err := s.Client.GetDel(ctx, key).Result()
	if errors.Is(err, goredis.Nil) {
		return "", ErrMiss
	}
	if err != nil {
		return "", fmt.Errorf("getdel raw one-time: %w", err)
	}
	return value, nil
}

// SaveVerificationCode stores a numeric verification code for the given purpose
// and email, resetting the failed-attempt counter so a freshly issued code
// always starts with a full attempt budget.
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
// and deletes the key only on a match or once the attempt budget is spent, so a
// single wrong guess cannot burn the valid code while the spent budget caps the
// guess space.
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

// maximumVerificationCodeAttempts bounds guesses per issued code: five leaves
// room for typos while capping brute-force success.
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

// getLoginFailuresScript reads the failure counter and its TTL in one round
// trip. A missing key (no failures yet) reports a zero count; the counter is
// otherwise indistinguishable from a zero TTL once it has expired.
const getLoginFailuresScript = `
local count = redis.call("GET", KEYS[1])
if not count then
  return {0, 0}
end
return {tonumber(count), redis.call("PTTL", KEYS[1])}
`

// GetLoginFailures reads the current password-login failure counter without
// mutating it, returning the count and TTL in one Lua call.
func (s Store) GetLoginFailures(ctx context.Context, email string) (LoginFailureState, error) {
	if s.Client == nil || email == "" {
		return LoginFailureState{}, fmt.Errorf("get login failures: %w", ErrInvalidArgument)
	}
	values, err := s.Client.Eval(ctx, getLoginFailuresScript, []string{s.Keys.LoginFailure(email)}).Slice()
	if err != nil {
		return LoginFailureState{}, fmt.Errorf("get login failures eval: %w", err)
	}
	if len(values) != 2 {
		return LoginFailureState{}, fmt.Errorf("get login failures eval: unexpected result")
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
