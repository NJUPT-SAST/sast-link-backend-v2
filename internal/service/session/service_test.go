package session

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/mailer"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }

type repeatedReader byte

func (r repeatedReader) Read(target []byte) (int, error) {
	for i := range target {
		target[i] = byte(r)
	}
	return len(target), nil
}

type fakeUsers struct {
	byLogin map[string]*model.User
	byID    map[int64]*model.User
	err     error
	lookups []string
	// tokens lets the fake mirror the repository's atomic
	// password-update-plus-revocation transaction.
	tokens            *fakeTokens
	updatePasswordErr error
	passwordUpdates   []int64
	// createErr forces CreateWithProfile to fail, for racing-insert scenarios the
	// in-memory maps cannot reproduce.
	createErr error
	// otherMailIdentities holds provider_id -> user_id for other_mail identities,
	// so ExistsAsEmailAnywhere can mirror the cross-table uniqueness check.
	otherMailIdentities map[string]int64
}

func (f *fakeUsers) FindByLoginIdentifier(_ context.Context, identifier string) (*model.User, error) {
	f.lookups = append(f.lookups, identifier)
	if f.err != nil {
		return nil, f.err
	}
	user, ok := f.byLogin[identifier]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return user, nil
}

func (f *fakeUsers) FindByLoginEmail(_ context.Context, email string) (*model.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	user, ok := f.byLogin[email]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return user, nil
}

func (f *fakeUsers) FindByID(_ context.Context, userID int64) (*model.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	user, ok := f.byID[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return user, nil
}

func (f *fakeUsers) ExistsByLoginEmail(_ context.Context, email string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	_, ok := f.byLogin[email]
	return ok, nil
}

func (f *fakeUsers) ExistsByStudentID(_ context.Context, studentID string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	for _, user := range f.byLogin {
		if user.StudentID == studentID {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeUsers) ExistsAsEmailAnywhere(_ context.Context, email string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if _, ok := f.byLogin[email]; ok {
		return true, nil
	}
	if f.otherMailIdentities != nil {
		if _, ok := f.otherMailIdentities[email]; ok {
			return true, nil
		}
	}
	return false, nil
}

// uniqueViolation reproduces what PostgreSQL actually returns for a duplicate
// key on the "user" table, including the constraint name the service dispatches
// on. Verified against PostgreSQL 16 in internal/repository integration tests.
func uniqueViolation(constraint string) error {
	return &pgconn.PgError{
		Code:           pgerrcode.UniqueViolation,
		TableName:      "user",
		ConstraintName: constraint,
	}
}

func (f *fakeUsers) CreateWithProfile(_ context.Context, user *model.User, _ *model.Profile) error {
	if f.err != nil {
		return f.err
	}
	if f.createErr != nil {
		return f.createErr
	}
	if f.byLogin == nil {
		f.byLogin = map[string]*model.User{}
	}
	if _, ok := f.byLogin[user.LoginEmail]; ok {
		return uniqueViolation(userLoginEmailConstraint)
	}
	for _, existing := range f.byLogin {
		if existing.StudentID == user.StudentID {
			return uniqueViolation(userStudentIDConstraint)
		}
	}
	if f.byID == nil {
		f.byID = map[int64]*model.User{}
	}
	user.ID = int64(len(f.byID) + 1)
	f.byLogin[user.LoginEmail] = user
	f.byID[user.ID] = user
	return nil
}

func (f *fakeUsers) UpdatePasswordAndRevokeSessions(
	ctx context.Context,
	userID int64,
	passwordHash string,
	revokedAt time.Time,
) ([]model.BlacklistEntry, error) {
	if f.updatePasswordErr != nil {
		return nil, f.updatePasswordErr
	}
	user, ok := f.byID[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	user.PasswordHash = passwordHash
	user.TokenVersion++
	f.passwordUpdates = append(f.passwordUpdates, userID)
	if f.tokens == nil {
		return nil, nil
	}
	// Mirror the repository: the real implementation revokes sessions in the
	// same transaction that rewrites the password.
	return f.tokens.RevokeAllByUser(ctx, userID, revokedAt)
}

type fakeClients struct {
	byClientID map[string]*model.OAuthClient
}

func (f *fakeClients) FindActiveByClientID(_ context.Context, clientID string) (*model.OAuthClient, error) {
	client, ok := f.byClientID[clientID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return client, nil
}

type fakeTokens struct {
	accessByJTI         map[string]*model.OAuthAccessToken
	refreshByHash       map[string]*model.OAuthRefreshToken
	createdAccess       *model.OAuthAccessToken
	createdRefresh      *model.OAuthRefreshToken
	rotatedAccess       *model.OAuthAccessToken
	rotatedRefresh      *model.OAuthRefreshToken
	revokedFamilies     []string
	revokedUsers        []int64
	revokeContextErr    error
	revokeContextHasTTL bool
	rotateErr           error
	revokeErr           error
}

func newFakeTokens() *fakeTokens {
	return &fakeTokens{accessByJTI: map[string]*model.OAuthAccessToken{}, refreshByHash: map[string]*model.OAuthRefreshToken{}}
}

func (f *fakeTokens) CreatePair(_ context.Context, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) error {
	f.createdAccess = access
	f.createdRefresh = refresh
	f.accessByJTI[access.TokenID] = access
	f.refreshByHash[refresh.TokenHash] = refresh
	return nil
}

func (f *fakeTokens) RotateRefreshToken(_ context.Context, currentHash string, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) error {
	if f.rotateErr != nil {
		if errors.Is(f.rotateErr, repository.ErrTokenReplay) {
			if current := f.refreshByHash[currentHash]; current != nil {
				f.revokedFamilies = append(f.revokedFamilies, current.FamilyID)
			}
		}
		return f.rotateErr
	}
	current, ok := f.refreshByHash[currentHash]
	if !ok {
		return repository.ErrNotFound
	}
	now := time.Now().UTC()
	current.RevokedAt = &now
	f.rotatedAccess = access
	f.rotatedRefresh = refresh
	f.accessByJTI[access.TokenID] = access
	f.refreshByHash[refresh.TokenHash] = refresh
	return nil
}

func (f *fakeTokens) FindRefreshToken(_ context.Context, tokenHash string) (*model.OAuthRefreshToken, error) {
	refresh, ok := f.refreshByHash[tokenHash]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return refresh, nil
}

func (f *fakeTokens) FindAccessTokenByJTI(_ context.Context, jti string) (*model.OAuthAccessToken, error) {
	access, ok := f.accessByJTI[jti]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return access, nil
}

func (f *fakeTokens) RevokeFamily(ctx context.Context, familyID string, revokedAt time.Time) ([]model.BlacklistEntry, error) {
	f.revokeContextErr = ctx.Err()
	_, f.revokeContextHasTTL = ctx.Deadline()
	if f.revokeErr != nil {
		return nil, f.revokeErr
	}
	f.revokedFamilies = append(f.revokedFamilies, familyID)
	entries := make([]model.BlacklistEntry, 0)
	for _, access := range f.accessByJTI {
		if access.FamilyID == nil || *access.FamilyID != familyID {
			continue
		}
		if access.ExpiresAt.After(revokedAt) {
			entries = append(entries, model.BlacklistEntry{TokenID: access.TokenID, ExpiresAt: access.ExpiresAt})
		}
		access.RevokedAt = &revokedAt
	}
	for _, refresh := range f.refreshByHash {
		if refresh.FamilyID == familyID {
			refresh.RevokedAt = &revokedAt
		}
	}
	return entries, nil
}

func (f *fakeTokens) RevokeAllByUser(_ context.Context, userID int64, revokedAt time.Time) ([]model.BlacklistEntry, error) {
	if f.revokeErr != nil {
		return nil, f.revokeErr
	}
	f.revokedUsers = append(f.revokedUsers, userID)
	entries := make([]model.BlacklistEntry, 0)
	for _, access := range f.accessByJTI {
		if access.UserID != userID {
			continue
		}
		if access.RevokedAt == nil && access.ExpiresAt.After(revokedAt) {
			entries = append(entries, model.BlacklistEntry{TokenID: access.TokenID, ExpiresAt: access.ExpiresAt})
		}
		access.RevokedAt = &revokedAt
	}
	for _, refresh := range f.refreshByHash {
		if refresh.UserID == userID {
			refresh.RevokedAt = &revokedAt
		}
	}
	return entries, nil
}

type fakeAudit struct {
	entries []model.AuditLog
	err     error
}

func (f *fakeAudit) Create(_ context.Context, entry *model.AuditLog) error {
	if f.err != nil {
		return f.err
	}
	f.entries = append(f.entries, *entry)
	return nil
}

type fakeLimiter struct {
	result LimitResult
	err    error
	calls  []string
}

func (f *fakeLimiter) Allow(_ context.Context, endpoint, subject string) (LimitResult, error) {
	f.calls = append(f.calls, endpoint+":"+subject)
	if f.err != nil {
		return LimitResult{}, f.err
	}
	if f.result == (LimitResult{}) {
		return LimitResult{Allowed: true}, nil
	}
	return f.result, nil
}

type fakeFailures struct {
	locked   bool
	retry    time.Duration
	failures []string
	resets   []string
	counts   map[string]int
	err      error
	resetErr error
}

func (f *fakeFailures) IsLocked(_ context.Context, key string) (bool, time.Duration, error) {
	if f.err != nil {
		return false, 0, f.err
	}
	if f.counts != nil && f.counts[key] >= 10 {
		return true, f.retry, nil
	}
	return f.locked, f.retry, nil
}

func (f *fakeFailures) RecordFailure(_ context.Context, key string) (LoginFailureResult, error) {
	if f.err != nil {
		return LoginFailureResult{}, f.err
	}
	f.failures = append(f.failures, key)
	if f.counts == nil {
		f.counts = make(map[string]int)
	}
	f.counts[key]++
	return LoginFailureResult{Count: f.counts[key], TTL: f.retry, Locked: f.counts[key] >= 10}, nil
}

func (f *fakeFailures) Reset(_ context.Context, key string) error {
	if f.resetErr != nil {
		return f.resetErr
	}
	if f.err != nil {
		return f.err
	}
	f.resets = append(f.resets, key)
	if f.counts != nil {
		delete(f.counts, key)
	}
	return nil
}

type fakeBlacklist struct {
	jti     string
	ttl     time.Duration
	entries map[string]time.Duration
	err     error
}

func (f *fakeBlacklist) BlacklistJTI(_ context.Context, jti string, ttl time.Duration) error {
	if f.err != nil {
		return f.err
	}
	f.jti = jti
	f.ttl = ttl
	return nil
}

func (f *fakeBlacklist) BlacklistJTIBatch(_ context.Context, entries map[string]time.Duration) error {
	if f.err != nil {
		return f.err
	}
	f.entries = entries
	for jti, ttl := range entries {
		f.jti = jti
		f.ttl = ttl
	}
	return nil
}

type fakeMailer struct {
	sent []fakeMail
	err  error
}

type fakeMail struct {
	to   string
	code string
}

func (f *fakeMailer) SendVerificationCode(_ context.Context, to, code string, _ mailer.VerificationPurpose) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, fakeMail{to: to, code: code})
	return nil
}

// fakeVerificationCodeStore mirrors the Redis store: a wrong guess costs one
// attempt but leaves the code usable until the budget is spent.
type fakeVerificationCodeStore struct {
	codes       map[string]string
	attempts    map[string]int
	attemptCap  int
	err         error
	discardErr  error
	discarded   []string
	verifyCalls int
}

func codeKey(purpose, email string) string { return purpose + "|" + email }

func (f *fakeVerificationCodeStore) SaveVerificationCode(_ context.Context, purpose, email, code string, _ time.Duration) error {
	if f.err != nil {
		return f.err
	}
	if f.codes == nil {
		f.codes = map[string]string{}
	}
	f.codes[codeKey(purpose, email)] = code
	delete(f.attempts, codeKey(purpose, email))
	return nil
}

func (f *fakeVerificationCodeStore) VerifyVerificationCode(_ context.Context, purpose, email, code string) (bool, int, error) {
	f.verifyCalls++
	if f.err != nil {
		return false, 0, f.err
	}
	key := codeKey(purpose, email)
	stored, ok := f.codes[key]
	if !ok {
		return false, 0, nil
	}
	if stored == code {
		delete(f.codes, key)
		delete(f.attempts, key)
		return true, 0, nil
	}
	if f.attempts == nil {
		f.attempts = map[string]int{}
	}
	limit := f.attemptCap
	if limit <= 0 {
		limit = 5
	}
	f.attempts[key]++
	if f.attempts[key] >= limit {
		delete(f.codes, key)
		delete(f.attempts, key)
		return false, 0, nil
	}
	return false, limit - f.attempts[key], nil
}

func (f *fakeVerificationCodeStore) DiscardVerificationCode(_ context.Context, purpose, email string) error {
	if f.discardErr != nil {
		return f.discardErr
	}
	key := codeKey(purpose, email)
	f.discarded = append(f.discarded, key)
	delete(f.codes, key)
	delete(f.attempts, key)
	return nil
}

type fakeRegisterTicketStore struct {
	tickets    map[string]string
	err        error
	consumeErr error
}

func (f *fakeRegisterTicketStore) SaveRegisterTicket(_ context.Context, ticket, email string, _ time.Duration) error {
	if f.err != nil {
		return f.err
	}
	if f.tickets == nil {
		f.tickets = map[string]string{}
	}
	f.tickets[ticket] = email
	return nil
}

func (f *fakeRegisterTicketStore) PeekRegisterTicket(_ context.Context, ticket string) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	email, ok := f.tickets[ticket]
	if !ok {
		return "", false, nil
	}
	return email, true, nil
}

func (f *fakeRegisterTicketStore) ConsumeRegisterTicket(_ context.Context, ticket string) error {
	if f.consumeErr != nil {
		return f.consumeErr
	}
	delete(f.tickets, ticket)
	return nil
}

type fakeIdentities struct {
	byProviderID map[string]*model.Identity
	err          error
	createErr    error
}

func (f *fakeIdentities) CountByUserAndProvider(_ context.Context, userID int64, _ model.LoginMethod) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	var count int64
	for _, identity := range f.byProviderID {
		if identity.UserID == userID {
			count++
		}
	}
	return count, nil
}

func (f *fakeIdentities) FindByProviderID(_ context.Context, _ model.LoginMethod, providerID string) (*model.Identity, error) {
	if f.err != nil {
		return nil, f.err
	}
	identity, ok := f.byProviderID[providerID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return identity, nil
}

func (f *fakeIdentities) CreateWithinLimit(_ context.Context, identity *model.Identity, limit int64) error {
	if f.createErr != nil {
		return f.createErr
	}
	if f.byProviderID == nil {
		f.byProviderID = map[string]*model.Identity{}
	}
	if _, ok := f.byProviderID[identity.ProviderID]; ok {
		return errors.New("duplicate identity")
	}
	var count int64
	for _, existing := range f.byProviderID {
		if existing.UserID == identity.UserID && existing.Provider == identity.Provider {
			count++
		}
	}
	if count >= limit {
		return repository.ErrLimitExceeded
	}
	f.byProviderID[identity.ProviderID] = identity
	return nil
}

type fakeBindTicketStore struct {
	tickets    map[string]BindTicketPayload
	err        error
	consumeErr error
}

func (f *fakeBindTicketStore) SaveBindTicket(_ context.Context, ticket string, payload BindTicketPayload, _ time.Duration) error {
	if f.err != nil {
		return f.err
	}
	if f.tickets == nil {
		f.tickets = map[string]BindTicketPayload{}
	}
	f.tickets[ticket] = payload
	return nil
}

func (f *fakeBindTicketStore) PeekBindTicket(_ context.Context, ticket string) (BindTicketPayload, bool, error) {
	if f.err != nil {
		return BindTicketPayload{}, false, f.err
	}
	payload, ok := f.tickets[ticket]
	if !ok {
		return BindTicketPayload{}, false, nil
	}
	return payload, true, nil
}

func (f *fakeBindTicketStore) ConsumeBindTicket(_ context.Context, ticket string) (bool, error) {
	if f.consumeErr != nil {
		return false, f.consumeErr
	}
	if _, ok := f.tickets[ticket]; !ok {
		return false, nil
	}
	delete(f.tickets, ticket)
	return true, nil
}

func TestLoginNormalizesIssuesTokensAndAudits(t *testing.T) {
	service, users, _, tokens, audit, failures := newTestService(t)
	result, err := service.Login(context.Background(), LoginInput{Identifier: "  USER@Njupt.edu.cn ", Password: "secret", ClientIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if users.lookups[0] != "user@njupt.edu.cn" {
		t.Fatalf("lookup identifier = %q, want normalized email", users.lookups[0])
	}
	if result.TokenType != BearerTokenType || result.Scope != "openid profile email" || result.RefreshToken == "" || result.AccessToken == "" {
		t.Fatalf("result = %+v, want bearer tokens with canonical scopes", result)
	}
	claims, err := service.JWT.VerifyAccessToken(result.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken returned error: %v", err)
	}
	if claims.Subject != "42" || claims.Scope != "openid profile email" || claims.ID != tokens.createdAccess.TokenID {
		t.Fatalf("claims = %+v, token metadata = %+v", claims, tokens.createdAccess)
	}
	if tokens.createdRefresh.Sequence != 0 || tokens.createdAccess.FamilyID == nil || *tokens.createdAccess.FamilyID != tokens.createdRefresh.FamilyID {
		t.Fatalf("created token pair = %+v / %+v, want initial same family", tokens.createdAccess, tokens.createdRefresh)
	}
	if len(failures.resets) != 1 || failures.resets[0] != "user:42" {
		t.Fatalf("failure resets = %#v, want user key reset", failures.resets)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "login" || audit.entries[0].Success == nil || !*audit.entries[0].Success {
		t.Fatalf("audit entries = %#v, want successful login audit", audit.entries)
	}
	if got := service.Limiter.(*fakeLimiter).calls[0]; got != "login:127.0.0.1" {
		t.Fatalf("limiter subject = %q, want client IP", got)
	}
	detail := string(audit.entries[0].Detail)
	if !strings.Contains(detail, `"method":"password"`) || strings.Contains(detail, "identifier") {
		t.Fatalf("audit detail = %s, want method only", detail)
	}
}

func TestLoginFailuresAreTypedAndCounted(t *testing.T) {
	service, _, _, _, audit, failures := newTestService(t)
	_, err := service.Login(context.Background(), LoginInput{Identifier: "missing@sast.fun", Password: "secret"})
	assertKind(t, err, KindUnknownIdentifier, errcode.CodeUnknownIdentifier)
	if len(failures.failures) != 1 || failures.failures[0] != "identifier:missing@sast.fun" {
		t.Fatalf("failures = %#v, want unknown bucket counted", failures.failures)
	}
	if got := lastErrCode(audit); got != errcode.CodeUnknownIdentifier {
		t.Fatalf("audit err code = %d, want %d", got, errcode.CodeUnknownIdentifier)
	}

	_, err = service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "wrong"})
	assertKind(t, err, KindPasswordInvalid, errcode.CodePasswordInvalid)
	if len(failures.failures) != 2 || failures.failures[1] != "user:42" {
		t.Fatalf("failures = %#v, want known user bucket", failures.failures)
	}
	if got := lastErrCode(audit); got != errcode.CodePasswordInvalid {
		t.Fatalf("audit err code = %d, want %d", got, errcode.CodePasswordInvalid)
	}
}

func TestServiceErrorsMatchSentinels(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)

	_, err := service.Login(context.Background(), LoginInput{Identifier: "missing@sast.fun", Password: "secret"})
	if !errors.Is(err, ErrUnknownIdentifier) {
		t.Fatalf("unknown identifier: errors.Is(err, ErrUnknownIdentifier) = false, err=%v", err)
	}

	_, err = service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "wrong"})
	if !errors.Is(err, ErrPasswordInvalid) {
		t.Fatalf("password invalid: errors.Is(err, ErrPasswordInvalid) = false, err=%v", err)
	}

	_, err = service.Refresh(context.Background(), RefreshInput{RefreshToken: ""})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid input: errors.Is(err, ErrInvalidInput) = false, err=%v", err)
	}

	_, err = service.Refresh(context.Background(), RefreshInput{RefreshToken: "unknown"})
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("invalid token: errors.Is(err, ErrInvalidToken) = false, err=%v", err)
	}

	tokens.revokeErr = nil
	_, err = service.Profile(context.Background(), ProfileInput{UserID: 999})
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("profile invalid token: errors.Is(err, ErrInvalidToken) = false, err=%v", err)
	}

	// A contextual error must still match its sentinel via the Is override,
	// even when it wraps an underlying cause.
	wrapped := newError(ErrInvalidToken, "custom context", errors.New("db down"))
	if !errors.Is(wrapped, ErrInvalidToken) {
		t.Fatalf("wrapped error did not match sentinel, err=%v", wrapped)
	}
}

func TestLoginLockAndLimiterShortCircuit(t *testing.T) {
	service, users, _, _, _, failures := newTestService(t)
	failures.locked = true
	_, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	assertKind(t, err, KindLocked, errcode.CodeRateLimited)
	if len(users.lookups) != 1 {
		t.Fatalf("user lookups = %#v, want known-user lookup before user-key lockout", users.lookups)
	}

	limitedService, limitedUsers, _, _, _, _ := newTestService(t)
	limitedService.Limiter = &fakeLimiter{result: LimitResult{Allowed: false, RetryAfter: time.Minute}}
	_, err = limitedService.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	assertKind(t, err, KindRateLimited, errcode.CodeRateLimited)
	if len(limitedUsers.lookups) != 0 {
		t.Fatalf("user lookups = %#v, want endpoint limiter before repository", limitedUsers.lookups)
	}
}

// Redis-backed throttling has no durable fallback, so an outage must degrade to
// "allow" rather than take login down entirely.
func TestLoginAllowsWhenLimiterUnavailable(t *testing.T) {
	service, users, _, tokens, _, _ := newTestService(t)
	service.Limiter = &fakeLimiter{err: errors.New("redis unavailable")}
	result, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if result.AccessToken == "" || tokens.createdAccess == nil || len(users.lookups) != 1 {
		t.Fatalf("result=%+v created=%+v lookups=%#v, want issued pair", result, tokens.createdAccess, users.lookups)
	}
}

func TestLoginAllowsWhenLockoutStateUnavailable(t *testing.T) {
	service, _, _, tokens, _, failures := newTestService(t)
	failures.err = errors.New("redis unavailable")
	result, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if result.AccessToken == "" || tokens.createdAccess == nil {
		t.Fatalf("result=%+v created=%+v, want issued pair despite lockout outage", result, tokens.createdAccess)
	}
}

// A failed counter increment must not mask the real rejection reason with a 500.
func TestLoginReportsCredentialErrorWhenFailureCounterUnavailable(t *testing.T) {
	service, _, _, _, _, failures := newTestService(t)
	failures.err = errors.New("redis unavailable")
	_, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "wrong"})
	assertKind(t, err, KindPasswordInvalid, errcode.CodePasswordInvalid)
}

func TestLoginRejectsDeletedAndInvalidClient(t *testing.T) {
	service, _, clients, _, _, failures := newTestService(t)
	service.Users.(*fakeUsers).byLogin["deleted@sast.fun"] = testUser(t, 99, "deleted@sast.fun", model.UserStateDeleted)
	_, err := service.Login(context.Background(), LoginInput{Identifier: "deleted@sast.fun", Password: "secret"})
	assertKind(t, err, KindUserDeleted, errcode.CodeAccountDeleted)
	if len(failures.failures) != 0 {
		t.Fatalf("deleted login failures = %#v, want no credential failure count", failures.failures)
	}

	service.InternalClientID = "bad"
	secret := "hash"
	clients.byClientID["bad"] = &model.OAuthClient{ID: 2, ClientID: "bad", ClientType: model.ClientTypeFirstParty, ClientSecretHash: &secret, IsActive: boolPtr(true), Scopes: model.StringArray(sessionScopes)}
	_, err = service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	assertKind(t, err, KindInternal, errcode.CodeInternal)
}

func TestLoginOtherMailAuditsMethodWithoutIdentifier(t *testing.T) {
	service, _, _, _, audit, _ := newTestService(t)
	_, err := service.Login(context.Background(), LoginInput{Identifier: "alias@sast.fun", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	detail := string(audit.entries[len(audit.entries)-1].Detail)
	if !strings.Contains(detail, `"method":"other_mail"`) || strings.Contains(detail, "identifier") {
		t.Fatalf("audit detail = %s, want other_mail method only", detail)
	}
}

func TestLoginAuditFailureCompensatesCreatedFamily(t *testing.T) {
	service, _, _, tokens, audit, failures := newTestService(t)
	audit.err = errors.New("audit down")
	_, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	assertKind(t, err, KindInternal, errcode.CodeInternal)
	if tokens.createdAccess == nil || len(tokens.revokedFamilies) != 1 || tokens.revokedFamilies[0] != tokens.createdRefresh.FamilyID {
		t.Fatalf("created=%+v revoked=%#v, want revoke compensation after post-issue audit failure", tokens.createdAccess, tokens.revokedFamilies)
	}
	if len(failures.resets) != 1 || failures.resets[0] != "user:42" {
		t.Fatalf("failure resets = %#v, want reset before success audit", failures.resets)
	}
}

// A lost counter reset leaves a stale count that expires with its own 15min
// window. Revoking the pair instead would make every login fail for the whole
// duration of a Redis outage, so the session is kept and the audit still runs.
func TestLoginKeepsSessionWhenFailureResetUnavailable(t *testing.T) {
	service, _, _, tokens, audit, failures := newTestService(t)
	failures.resetErr = errors.New("redis down")
	result, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if result.AccessToken == "" || len(tokens.revokedFamilies) != 0 {
		t.Fatalf("result=%+v revoked=%#v, want issued pair with no compensation", result, tokens.revokedFamilies)
	}
	if len(audit.entries) != 1 || audit.entries[0].Success == nil || !*audit.entries[0].Success {
		t.Fatalf("audit entries = %#v, want successful login audit", audit.entries)
	}
}

func TestLoginCompensationDetachesRequestCancellation(t *testing.T) {
	service, _, _, tokens, audit, _ := newTestService(t)
	audit.err = errors.New("audit down")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := service.Login(ctx, LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	assertKind(t, err, KindInternal, errcode.CodeInternal)
	if len(tokens.revokedFamilies) != 1 {
		t.Fatalf("revoked families = %#v, want compensation after canceled request", tokens.revokedFamilies)
	}
	if tokens.revokeContextErr != nil {
		t.Fatalf("compensation context error = %v, want live context", tokens.revokeContextErr)
	}
	if !tokens.revokeContextHasTTL {
		t.Fatal("compensation context has no deadline")
	}
}

func TestRefreshRotatesSameFamilyAndScopes(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)
	login, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	refresh, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: login.RefreshToken})
	if err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	if refresh.RefreshToken == login.RefreshToken || refresh.Scope != "openid profile email" {
		t.Fatalf("refresh result = %+v, want rotated canonical token", refresh)
	}
	if tokens.rotatedRefresh.Sequence != tokens.createdRefresh.Sequence+1 || tokens.rotatedRefresh.FamilyID != tokens.createdRefresh.FamilyID {
		t.Fatalf("rotated refresh = %+v, current = %+v, want same family seq+1", tokens.rotatedRefresh, tokens.createdRefresh)
	}
	if ok, err := scope.Equal([]string(tokens.rotatedRefresh.Scopes), []string(tokens.createdRefresh.Scopes)); err != nil || !ok {
		t.Fatalf("rotated scopes = %#v current = %#v err=%v", tokens.rotatedRefresh.Scopes, tokens.createdRefresh.Scopes, err)
	}
}

func TestRefreshRejectsDeletedExpiredAndReplay(t *testing.T) {
	service, users, _, tokens, _, _ := newTestService(t)
	login, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	users.byID[42].State = model.UserStateDeleted
	_, err = service.Refresh(context.Background(), RefreshInput{RefreshToken: login.RefreshToken})
	assertKind(t, err, KindUserDeleted, errcode.CodeAccountDeleted)

	users.byID[42].State = model.UserStateOnSAST
	tokens.createdRefresh.ClientID = 2
	_, err = service.Refresh(context.Background(), RefreshInput{RefreshToken: login.RefreshToken})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)
	tokens.createdRefresh.ClientID = 1
	tokens.rotateErr = repository.ErrTokenReplay
	_, err = service.Refresh(context.Background(), RefreshInput{RefreshToken: login.RefreshToken})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)
	if len(tokens.revokedFamilies) == 0 {
		t.Fatalf("expected fake repository to record family revoke on replay")
	}
}

func TestRefreshRevokedTokenRevokesFamilyBeforeOtherPrechecks(t *testing.T) {
	service, users, _, tokens, _, _ := newTestService(t)
	blacklist := &fakeBlacklist{}
	service.Blacklist = blacklist
	login, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	now := service.now()
	tokens.createdRefresh.RevokedAt = &now
	tokens.createdRefresh.ExpiresAt = now.Add(-time.Second)
	tokens.createdRefresh.ClientID = 99
	users.byID[42].State = model.UserStateDeleted

	_, err = service.Refresh(context.Background(), RefreshInput{RefreshToken: login.RefreshToken})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)
	if len(tokens.revokedFamilies) != 1 || tokens.revokedFamilies[0] != tokens.createdRefresh.FamilyID {
		t.Fatalf("revoked families = %#v, want revoked refresh family", tokens.revokedFamilies)
	}
	if blacklist.jti == "" || blacklist.ttl <= 0 {
		t.Fatalf("blacklist = %+v, want live revoked access token delivery", blacklist)
	}
}

func TestRefreshExpiredActiveTokenDoesNotRevokeFamily(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)
	login, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	tokens.createdRefresh.ExpiresAt = service.now().Add(-time.Second)

	_, err = service.Refresh(context.Background(), RefreshInput{RefreshToken: login.RefreshToken})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)
	if len(tokens.revokedFamilies) != 0 {
		t.Fatalf("revoked families = %#v, want no revoke for active expired token", tokens.revokedFamilies)
	}
}

func TestRefreshAuditsSuccessAndReplay(t *testing.T) {
	service, _, _, tokens, audit, _ := newTestService(t)
	login, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}

	refresh, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: login.RefreshToken})
	if err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	if refresh.RefreshToken == "" {
		t.Fatal("Refresh returned empty token")
	}
	var successEntry *model.AuditLog
	for i := range audit.entries {
		if audit.entries[i].Action == "refresh" {
			successEntry = &audit.entries[i]
		}
	}
	if successEntry == nil || successEntry.Success == nil || !*successEntry.Success {
		t.Fatalf("audit entries = %#v, want successful refresh audit", audit.entries)
	}

	tokens.rotateErr = repository.ErrTokenReplay
	_, err = service.Refresh(context.Background(), RefreshInput{RefreshToken: refresh.RefreshToken})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)
	last := audit.entries[len(audit.entries)-1]
	if last.Action != "refresh" || last.Success == nil || *last.Success || last.ErrCode == nil || *last.ErrCode != errcode.CodeAccessTokenInvalid {
		t.Fatalf("last audit = %+v, want failed refresh audit with invalid-token code", last)
	}
}

func TestLoginLockoutBoundaryAndAliasReset(t *testing.T) {
	service, _, _, _, _, failures := newTestService(t)
	failures.retry = time.Minute

	for attempt := 1; attempt <= 9; attempt++ {
		_, err := service.Login(context.Background(), LoginInput{Identifier: "alias@sast.fun", Password: "wrong"})
		assertKind(t, err, KindPasswordInvalid, errcode.CodePasswordInvalid)
	}
	if failures.counts["user:42"] != 9 {
		t.Fatalf("failure count = %d, want 9", failures.counts["user:42"])
	}

	_, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "wrong"})
	assertKind(t, err, KindLocked, errcode.CodeRateLimited)
	if failures.counts["user:42"] != 10 {
		t.Fatalf("failure count = %d, want 10", failures.counts["user:42"])
	}

	_, err = service.Login(context.Background(), LoginInput{Identifier: "alias@sast.fun", Password: "wrong"})
	assertKind(t, err, KindLocked, errcode.CodeRateLimited)
	if failures.counts["user:42"] != 10 {
		t.Fatalf("failure count after locked attempt = %d, want 10", failures.counts["user:42"])
	}

	delete(failures.counts, "user:42")
	_, err = service.Login(context.Background(), LoginInput{Identifier: "alias@sast.fun", Password: "secret"})
	if err != nil {
		t.Fatalf("successful alias Login returned error: %v", err)
	}
	if len(failures.resets) == 0 || failures.resets[len(failures.resets)-1] != "user:42" {
		t.Fatalf("failure resets = %#v, want shared user key", failures.resets)
	}
}

func TestLogoutStrictOwnershipRevokesAndBlacklists(t *testing.T) {
	service, _, _, tokens, audit, _ := newTestService(t)
	blacklist := &fakeBlacklist{}
	service.Blacklist = blacklist
	login, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	claims, err := service.JWT.VerifyAccessToken(login.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken returned error: %v", err)
	}
	familyID := tokens.createdRefresh.FamilyID
	result, err := service.Logout(context.Background(), LogoutInput{PrincipalJTI: claims.ID, PrincipalUserID: 42, RefreshToken: login.RefreshToken})
	if err != nil {
		t.Fatalf("Logout returned error: %v", err)
	}
	if result.FamilyID != familyID || tokens.revokedFamilies[len(tokens.revokedFamilies)-1] != familyID || blacklist.jti != claims.ID || blacklist.ttl <= 0 {
		t.Fatalf("logout result=%+v revoked=%#v blacklist=%+v", result, tokens.revokedFamilies, blacklist)
	}
	if detail := string(audit.entries[len(audit.entries)-1].Detail); detail != "{}" {
		t.Fatalf("logout audit detail = %s, want {}", detail)
	}

	tokens.createdRefresh.ClientID = 2
	_, err = service.Logout(context.Background(), LogoutInput{PrincipalJTI: claims.ID, PrincipalUserID: 42, RefreshToken: login.RefreshToken})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)
}

func TestLogoutRevokeFamilyBeforeBlacklistAndRetry(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)
	blacklist := &fakeBlacklist{err: errors.New("redis down")}
	service.Blacklist = blacklist
	login, claims := loginForLogout(t, &service)
	_, err := service.Logout(context.Background(), LogoutInput{PrincipalJTI: claims.ID, PrincipalUserID: 42, RefreshToken: login.RefreshToken})
	if err != nil {
		t.Fatalf("Logout returned error after Redis failure: %v", err)
	}
	if len(tokens.revokedFamilies) != 1 {
		t.Fatalf("revoked families = %#v, want DB revoke before blacklist failure", tokens.revokedFamilies)
	}

	blacklist.err = nil
	_, err = service.Logout(context.Background(), LogoutInput{PrincipalJTI: claims.ID, PrincipalUserID: 42, RefreshToken: login.RefreshToken})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)

	service, _, _, tokens, _, _ = newTestService(t)
	blacklist = &fakeBlacklist{}
	service.Blacklist = blacklist
	tokens.revokeErr = errors.New("db down")
	login, claims = loginForLogout(t, &service)
	_, err = service.Logout(context.Background(), LogoutInput{PrincipalJTI: claims.ID, PrincipalUserID: 42, RefreshToken: login.RefreshToken})
	assertKind(t, err, KindInternal, errcode.CodeInternal)
	if blacklist.jti != "" {
		t.Fatalf("blacklist jti = %q, want no blacklist when DB revoke fails", blacklist.jti)
	}
}

func TestLogoutAuditFailureIsFailOpen(t *testing.T) {
	service, _, _, _, audit, _ := newTestService(t)
	login, claims := loginForLogout(t, &service)
	audit.err = errors.New("audit down")

	result, err := service.Logout(context.Background(), LogoutInput{
		PrincipalJTI:    claims.ID,
		PrincipalUserID: 42,

		RefreshToken: login.RefreshToken,
	})
	if err != nil {
		t.Fatalf("Logout returned error after audit failure: %v", err)
	}
	if result.FamilyID == "" {
		t.Fatal("logout result missing family ID")
	}
}

func TestLogoutRejectsRevokedMetadataAndExpiredMetadata(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)
	login, claims := loginForLogout(t, &service)
	now := service.now()

	tokens.createdAccess.RevokedAt = &now
	_, err := service.Logout(context.Background(), LogoutInput{PrincipalJTI: claims.ID, PrincipalUserID: 42, RefreshToken: login.RefreshToken})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)
	tokens.createdAccess.RevokedAt = nil

	tokens.createdAccess.ExpiresAt = now.Add(-time.Second)
	_, err = service.Logout(context.Background(), LogoutInput{PrincipalJTI: claims.ID, PrincipalUserID: 42, RefreshToken: login.RefreshToken})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)
	tokens.createdAccess.ExpiresAt = login.AccessExpiresAt
	tokens.createdAccess.RevokedAt = nil
	tokens.createdRefresh.RevokedAt = &now
	_, err = service.Logout(context.Background(), LogoutInput{PrincipalJTI: claims.ID, PrincipalUserID: 42, RefreshToken: login.RefreshToken})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)
	tokens.createdRefresh.RevokedAt = nil

	tokens.createdRefresh.ExpiresAt = now.Add(-time.Second)
	_, err = service.Logout(context.Background(), LogoutInput{PrincipalJTI: claims.ID, PrincipalUserID: 42, RefreshToken: login.RefreshToken})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)
}

func TestProfileDTOExcludesSecrets(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	profile, err := service.Profile(context.Background(), ProfileInput{UserID: 42})
	if err != nil {
		t.Fatalf("Profile returned error: %v", err)
	}
	if profile.Profile.ID != 42 || profile.Profile.LoginEmail != "user@njupt.edu.cn" || profile.Profile.Profile == nil || profile.Profile.Profile.Nickname == nil || *profile.Profile.Profile.Nickname != "pt" || len(profile.Profile.Identities) != 1 {
		t.Fatalf("profile = %+v, want explicit API DTO", profile.Profile)
	}
	if profile.Profile.Identities[0].Provider != string(model.LoginMethodGitHub) || profile.Profile.Identities[0].ProviderID == "" {
		t.Fatalf("identities = %#v, want safe identity DTO", profile.Profile.Identities)
	}
}

func TestVerifyRegisterCodeIssuesTicket(t *testing.T) {
	service := newRegisterService(t)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	registerPurpose := string(mailer.VerificationPurposeRegister)
	if err := codes.SaveVerificationCode(context.Background(), registerPurpose, "new@sast.fun", "123456", time.Minute); err != nil {
		t.Fatalf("save verification code: %v", err)
	}

	result, err := service.VerifyRegisterCode(context.Background(), VerifyRegisterCodeInput{Email: "new@sast.fun", Code: "123456"})
	if err != nil {
		t.Fatalf("VerifyRegisterCode returned error: %v", err)
	}
	if result.RegisterTicket == "" || result.Email != "new@sast.fun" || result.ExpiresIn != 300 {
		t.Fatalf("result = %+v, want ticket, email and 300s expiry", result)
	}
	if _, ok := codes.codes[codeKey(registerPurpose, "new@sast.fun")]; ok {
		t.Fatal("verification code was not consumed")
	}
}

func TestVerifyRegisterCodeRejectsWrongOrExpiredCode(t *testing.T) {
	service := newRegisterService(t)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	if err := codes.SaveVerificationCode(context.Background(), string(mailer.VerificationPurposeRegister), "new@sast.fun", "123456", time.Minute); err != nil {
		t.Fatalf("save verification code: %v", err)
	}

	_, err := service.VerifyRegisterCode(context.Background(), VerifyRegisterCodeInput{Email: "new@sast.fun", Code: "000000"})
	assertKind(t, err, KindInvalidInput, errcode.CodeVerificationCodeWrong)

	_, err = service.VerifyRegisterCode(context.Background(), VerifyRegisterCodeInput{Email: "missing@sast.fun", Code: "123456"})
	assertKind(t, err, KindInvalidInput, errcode.CodeVerificationCodeExpired)
}

func TestVerifyRegisterCodeRejectsCrossPurposeCode(t *testing.T) {
	service := newRegisterService(t)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	// A code issued for password reset must not satisfy register verification.
	if err := codes.SaveVerificationCode(context.Background(), string(mailer.VerificationPurposeResetPassword), "new@sast.fun", "123456", time.Minute); err != nil {
		t.Fatalf("save verification code: %v", err)
	}
	_, err := service.VerifyRegisterCode(context.Background(), VerifyRegisterCodeInput{Email: "new@sast.fun", Code: "123456"})
	assertKind(t, err, KindInvalidInput, errcode.CodeVerificationCodeExpired)
}

// Per the Redis degradation policy (PRD §6.0) limiter outages fail open; the
// verification-code store is the fail-closed guard when Redis is fully down.
func TestSendRegisterCodeRejectsHeaderInjectionPayload(t *testing.T) {
	// The go-playground "email" validator lets CR/LF through, so the service
	// layer must reject header-injection payloads before they reach the mailer
	// or Redis keys. Each entry point is covered.
	injection := "victim@gmail.com\r\nBcc: attacker@sast.fun"
	service := newRegisterService(t)

	_, err := service.SendRegisterCode(context.Background(), SendRegisterCodeInput{Email: injection})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)

	_, err = service.VerifyRegisterCode(context.Background(), VerifyRegisterCodeInput{Email: injection, Code: "123456"})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)

	_, err = service.ForgotPasswordSendCode(context.Background(), ForgotPasswordInput{Email: injection})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)

	_, err = service.ResetPassword(context.Background(), ResetPasswordInput{Email: injection, Code: "123456", Password: "longpassword"})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)

	_, err = service.BindEmailSendCode(context.Background(), BindEmailSendCodeInput{UserID: 42, Email: injection})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)

	// No mail must have been sent for any of the rejected payloads.
	if sent := len(service.Mailer.(*fakeMailer).sent); sent != 0 {
		t.Fatalf("mailer sent=%d, want 0 (injection payload reached the mailer)", sent)
	}
}

// The send-code response must not reveal whether the address owns an account:
// a "邮箱不存在" error tells unauthenticated callers exactly which inboxes are
// worth phishing. Known and unknown emails get the identical success shape;
// only the known one actually receives a code.
func TestForgotPasswordSendCodeHidesAccountExistence(t *testing.T) {
	t.Run("unknown email returns success without sending", func(t *testing.T) {
		service := newRegisterService(t)
		result, err := service.ForgotPasswordSendCode(context.Background(), ForgotPasswordInput{Email: "nobody@njupt.edu.cn"})
		if err != nil {
			t.Fatalf("ForgotPasswordSendCode returned error: %v", err)
		}
		if result.Email != "nobody@njupt.edu.cn" || result.ExpiresIn != 300 {
			t.Fatalf("result = %+v, want the same success shape as a known email", result)
		}
		if sent := len(service.Mailer.(*fakeMailer).sent); sent != 0 {
			t.Fatalf("mailer sent=%d, want 0 for unknown email", sent)
		}
	})

	t.Run("known email returns success and sends", func(t *testing.T) {
		service := newRegisterService(t)
		result, err := service.ForgotPasswordSendCode(context.Background(), ForgotPasswordInput{Email: "user@njupt.edu.cn"})
		if err != nil {
			t.Fatalf("ForgotPasswordSendCode returned error: %v", err)
		}
		if result.Email != "user@njupt.edu.cn" || result.ExpiresIn != 300 {
			t.Fatalf("result = %+v, want success shape", result)
		}
		if sent := len(service.Mailer.(*fakeMailer).sent); sent != 1 {
			t.Fatalf("mailer sent=%d, want 1 for known email", sent)
		}
	})
}

func TestSendRegisterCodeAllowsWhenEmailLimiterUnavailable(t *testing.T) {
	service := newRegisterService(t)
	service.EmailLimiter = &fakeLimiter{err: errors.New("redis unavailable")}
	service.EmailIPLimiter = &fakeLimiter{err: errors.New("redis unavailable")}
	result, err := service.SendRegisterCode(context.Background(), SendRegisterCodeInput{Email: "new@sast.fun", ClientIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("SendRegisterCode returned error: %v", err)
	}
	if result.Email != "new@sast.fun" || len(service.Mailer.(*fakeMailer).sent) != 1 {
		t.Fatalf("result=%+v sent=%d, want code delivered despite limiter outage", result, len(service.Mailer.(*fakeMailer).sent))
	}
}

func TestSendRegisterCodeRejectsWhenEmailLimitExceeded(t *testing.T) {
	service := newRegisterService(t)
	service.EmailLimiter = &fakeLimiter{result: LimitResult{Allowed: false, RetryAfter: time.Minute}}
	_, err := service.SendRegisterCode(context.Background(), SendRegisterCodeInput{Email: "new@sast.fun", ClientIP: "127.0.0.1"})
	assertKind(t, err, KindRateLimited, errcode.CodeRateLimited)

	service = newRegisterService(t)
	service.EmailIPLimiter = &fakeLimiter{result: LimitResult{Allowed: false, RetryAfter: time.Minute}}
	_, err = service.SendRegisterCode(context.Background(), SendRegisterCodeInput{Email: "new@sast.fun", ClientIP: "127.0.0.1"})
	assertKind(t, err, KindRateLimited, errcode.CodeRateLimited)
}

// Fail-closed stores (verification codes, tickets) must surface their outage as
// dependency_unavailable (503), never as a bare internal error (500): the PRD
// §6.0 policy rejects the request so the user can retry, while 500 would read
// as a server bug to clients and alerting.
func TestFailClosedStoresReturnDependencyUnavailable(t *testing.T) {
	redisDown := errors.New("redis connection refused")

	t.Run("send code", func(t *testing.T) {
		service := newRegisterService(t)
		service.VerificationCode = &fakeVerificationCodeStore{err: redisDown}
		_, err := service.SendRegisterCode(context.Background(), SendRegisterCodeInput{Email: "new@sast.fun"})
		assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	})

	t.Run("forgot password send code", func(t *testing.T) {
		service := newRegisterService(t)
		service.VerificationCode = &fakeVerificationCodeStore{err: redisDown}
		_, err := service.ForgotPasswordSendCode(context.Background(), ForgotPasswordInput{Email: "user@njupt.edu.cn"})
		assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	})

	t.Run("verify code", func(t *testing.T) {
		service := newRegisterService(t)
		service.VerificationCode = &fakeVerificationCodeStore{err: redisDown}
		_, err := service.VerifyRegisterCode(context.Background(), VerifyRegisterCodeInput{Email: "new@sast.fun", Code: "123456"})
		assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	})

	t.Run("reset password verify code", func(t *testing.T) {
		service := newRegisterService(t)
		service.VerificationCode = &fakeVerificationCodeStore{err: redisDown}
		_, err := service.ResetPassword(context.Background(), ResetPasswordInput{Email: "user@njupt.edu.cn", Code: "123456", Password: "longpassword"})
		assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	})

	t.Run("save register ticket", func(t *testing.T) {
		service := newRegisterService(t)
		service.RegisterTicket = &fakeRegisterTicketStore{err: redisDown}
		codes := service.VerificationCode.(*fakeVerificationCodeStore)
		if err := codes.SaveVerificationCode(context.Background(), string(mailer.VerificationPurposeRegister), "new@sast.fun", "123456", time.Minute); err != nil {
			t.Fatalf("save code: %v", err)
		}
		_, err := service.VerifyRegisterCode(context.Background(), VerifyRegisterCodeInput{Email: "new@sast.fun", Code: "123456"})
		assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	})

	t.Run("read register ticket", func(t *testing.T) {
		service := newRegisterService(t)
		service.RegisterTicket = &fakeRegisterTicketStore{err: redisDown}
		_, err := service.Register(context.Background(), RegisterInput{
			RegisterTicket: "reg_xxx",
			Password:       "newpassword",
			Name:           "New",
			StudentID:      "B24040099",
			PhoneNumber:    "13800138000",
			QQNumber:       "10000",
			College:        string(model.CollegeOther),
			Major:          "CS",
		})
		assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	})

	t.Run("bind send code", func(t *testing.T) {
		service := newRegisterService(t)
		service.VerificationCode = &fakeVerificationCodeStore{err: redisDown}
		_, err := service.BindEmailSendCode(context.Background(), BindEmailSendCodeInput{UserID: 42, Email: "extra@gmail.com"})
		assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	})

	t.Run("peek bind ticket", func(t *testing.T) {
		service := newRegisterService(t)
		service.BindTicket = &fakeBindTicketStore{err: redisDown}
		_, err := service.BindEmailVerify(context.Background(), BindEmailVerifyInput{UserID: 42, BindTicket: "be_xxx", Code: "123456"})
		assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	})

	t.Run("consume bind ticket", func(t *testing.T) {
		service := newRegisterService(t)
		bindTickets := service.BindTicket.(*fakeBindTicketStore)
		if err := bindTickets.SaveBindTicket(context.Background(), "be_xxx", BindTicketPayload{Email: "extra@gmail.com", UserID: 42}, time.Minute); err != nil {
			t.Fatalf("save bind ticket: %v", err)
		}
		codes := service.VerificationCode.(*fakeVerificationCodeStore)
		if err := codes.SaveVerificationCode(context.Background(), string(mailer.VerificationPurposeBindEmail), "extra@gmail.com", "123456", time.Minute); err != nil {
			t.Fatalf("save code: %v", err)
		}
		bindTickets.consumeErr = redisDown
		_, err := service.BindEmailVerify(context.Background(), BindEmailVerifyInput{UserID: 42, BindTicket: "be_xxx", Code: "123456"})
		assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	})
}

func TestRegisterCreatesUserAndIssuesTokens(t *testing.T) {
	service := newRegisterService(t)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_xxx", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("save register ticket: %v", err)
	}

	result, err := service.Register(context.Background(), RegisterInput{
		RegisterTicket: "reg_xxx",
		Password:       "newpassword",
		Name:           "New User",
		StudentID:      "B24040099",
		PhoneNumber:    "13800138000",
		QQNumber:       "10000",
		College:        string(model.CollegeOther),
		Major:          "CS",
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" || result.Profile.ID == 0 {
		t.Fatalf("result = %+v, want tokens and profile", result)
	}
	if result.Profile.LoginEmail != "new@sast.fun" {
		t.Fatalf("profile email = %q, want new@sast.fun", result.Profile.LoginEmail)
	}
}

func TestRegisterRejectsUsedTicket(t *testing.T) {
	service := newRegisterService(t)
	_, err := service.Register(context.Background(), RegisterInput{RegisterTicket: "reg_missing", Password: "newpassword", Name: "x", StudentID: "B1", PhoneNumber: "1", QQNumber: "1", College: string(model.CollegeOther), Major: "CS"})
	assertKind(t, err, KindInvalidToken, errcode.CodeRegisterTicketInvalid)
}

func TestRegisterRejectsInvalidCollege(t *testing.T) {
	service := newRegisterService(t)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_xxx", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("save register ticket: %v", err)
	}
	_, err := service.Register(context.Background(), RegisterInput{
		RegisterTicket: "reg_xxx",
		Password:       "newpassword",
		Name:           "New",
		StudentID:      "B24040099",
		PhoneNumber:    "13800138000",
		QQNumber:       "10000",
		College:        "不存在的学院",
		Major:          "CS",
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
	// The rejected request must not consume the one-time ticket.
	if _, ok := tickets.tickets["reg_xxx"]; !ok {
		t.Fatal("register ticket was consumed by invalid college input")
	}
}

func TestRegisterRejectsUnsupportedRegistrationState(t *testing.T) {
	service := newRegisterService(t)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_xxx", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("save register ticket: %v", err)
	}
	_, err := service.Register(context.Background(), RegisterInput{
		RegisterTicket:    "reg_xxx",
		Password:          "newpassword",
		Name:              "New",
		StudentID:         "B24040099",
		PhoneNumber:       "13800138000",
		QQNumber:          "10000",
		College:           string(model.CollegeOther),
		Major:             "CS",
		RegistrationState: "rs_abc",
		OAuthState:        "os_abc",
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
	if _, ok := tickets.tickets["reg_xxx"]; !ok {
		t.Fatal("register ticket was consumed by rejected registration_state input")
	}
}

func TestRegisterRejectsExistingEmail(t *testing.T) {
	service := newRegisterService(t)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_xxx", "user@njupt.edu.cn", time.Minute); err != nil {
		t.Fatalf("save register ticket: %v", err)
	}

	_, err := service.Register(context.Background(), RegisterInput{
		RegisterTicket: "reg_xxx",
		Password:       "newpassword",
		Name:           "Dup",
		StudentID:      "B24040099",
		PhoneNumber:    "13800138000",
		QQNumber:       "10000",
		College:        string(model.CollegeOther),
		Major:          "CS",
	})
	assertKind(t, err, KindConflict, errcode.CodeEmailAlreadyRegistered)
}

func TestRegisterRejectsEmailBoundAsOtherMailIdentity(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	users.otherMailIdentities = map[string]int64{
		"taken@sast.fun": 99,
	}
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_xxx", "taken@sast.fun", time.Minute); err != nil {
		t.Fatalf("save register ticket: %v", err)
	}

	_, err := service.Register(context.Background(), RegisterInput{
		RegisterTicket: "reg_xxx",
		Password:       "newpassword",
		Name:           "Dup",
		StudentID:      "B24040099",
		PhoneNumber:    "13800138000",
		QQNumber:       "10000",
		College:        string(model.CollegeOther),
		Major:          "CS",
	})
	assertKind(t, err, KindConflict, errcode.CodeEmailAlreadyRegistered)
}

func TestRegisterRejectsShortPassword(t *testing.T) {
	service := newRegisterService(t)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_xxx", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("save register ticket: %v", err)
	}

	_, err := service.Register(context.Background(), RegisterInput{
		RegisterTicket: "reg_xxx",
		Password:       "short",
		Name:           "New",
		StudentID:      "B24040099",
		PhoneNumber:    "13800138000",
		QQNumber:       "10000",
		College:        string(model.CollegeOther),
		Major:          "CS",
	})
	assertKind(t, err, KindValidationFailed, errcode.CodePasswordTooShort)
}

func TestBindEmailSendCodeIssuesTicket(t *testing.T) {
	service := newRegisterService(t)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	result, err := service.BindEmailSendCode(context.Background(), BindEmailSendCodeInput{UserID: 42, Email: "extra@gmail.com"})
	if err != nil {
		t.Fatalf("BindEmailSendCode returned error: %v", err)
	}
	if result.BindTicket == "" || result.ExpiresIn != 300 {
		t.Fatalf("result = %+v, want bind ticket and 300s expiry", result)
	}
	if _, ok := codes.codes[codeKey(string(mailer.VerificationPurposeBindEmail), "extra@gmail.com")]; !ok {
		t.Fatal("verification code not saved under bind_email purpose")
	}
}

func TestBindEmailSendCodeRejectsOccupiedEmail(t *testing.T) {
	service := newRegisterService(t)
	identities := service.Identities.(*fakeIdentities)
	identities.byProviderID = map[string]*model.Identity{
		"extra@gmail.com": {UserID: 99, Provider: model.LoginMethodOtherMail, ProviderID: "extra@gmail.com"},
	}
	_, err := service.BindEmailSendCode(context.Background(), BindEmailSendCodeInput{UserID: 42, Email: "extra@gmail.com"})
	assertKind(t, err, KindConflict, errcode.CodeIdentityOccupied)
}

// An address bound to the caller and an address bound to someone else must
// produce the identical conflict: distinct errors would let any authenticated
// user enumerate which inboxes other accounts use for login.
func TestBindEmailSendCodeSameConflictForSelfAndOtherBinding(t *testing.T) {
	selfBound := newRegisterService(t)
	selfBound.Identities = &fakeIdentities{byProviderID: map[string]*model.Identity{
		"extra@gmail.com": {UserID: 42, Provider: model.LoginMethodOtherMail, ProviderID: "extra@gmail.com"},
	}}
	_, selfErr := selfBound.BindEmailSendCode(context.Background(), BindEmailSendCodeInput{UserID: 42, Email: "extra@gmail.com"})
	assertKind(t, selfErr, KindConflict, errcode.CodeIdentityOccupied)

	otherBound := newRegisterService(t)
	otherBound.Identities = &fakeIdentities{byProviderID: map[string]*model.Identity{
		"extra@gmail.com": {UserID: 99, Provider: model.LoginMethodOtherMail, ProviderID: "extra@gmail.com"},
	}}
	_, otherErr := otherBound.BindEmailSendCode(context.Background(), BindEmailSendCodeInput{UserID: 42, Email: "extra@gmail.com"})
	assertKind(t, otherErr, KindConflict, errcode.CodeIdentityOccupied)

	selfServiceErr, _ := selfErr.(*Error)
	otherServiceErr, _ := otherErr.(*Error)
	if selfServiceErr.Message != otherServiceErr.Message {
		t.Fatalf("self message %q != other message %q", selfServiceErr.Message, otherServiceErr.Message)
	}
}

func TestBindEmailSendCodeRejectsLoginEmail(t *testing.T) {
	service := newRegisterService(t)
	_, err := service.BindEmailSendCode(context.Background(), BindEmailSendCodeInput{UserID: 42, Email: "user@njupt.edu.cn"})
	assertKind(t, err, KindConflict, errcode.CodeIdentityOccupied)
}

func TestBindEmailVerifyCreatesIdentity(t *testing.T) {
	service := newRegisterService(t)
	bindTickets := service.BindTicket.(*fakeBindTicketStore)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	if err := bindTickets.SaveBindTicket(context.Background(), "be_xxx", BindTicketPayload{Email: "extra@gmail.com", UserID: 42}, time.Minute); err != nil {
		t.Fatalf("save bind ticket: %v", err)
	}
	if err := codes.SaveVerificationCode(context.Background(), string(mailer.VerificationPurposeBindEmail), "extra@gmail.com", "123456", time.Minute); err != nil {
		t.Fatalf("save code: %v", err)
	}
	result, err := service.BindEmailVerify(context.Background(), BindEmailVerifyInput{UserID: 42, BindTicket: "be_xxx", Code: "123456"})
	if err != nil {
		t.Fatalf("BindEmailVerify returned error: %v", err)
	}
	if result.Email != "extra@gmail.com" || result.Identity.Provider != string(model.LoginMethodOtherMail) || result.Identity.ProviderID != "extra@gmail.com" {
		t.Fatalf("result = %+v, want bound other_mail identity", result)
	}
	identities := service.Identities.(*fakeIdentities)
	if identities.byProviderID["extra@gmail.com"] == nil {
		t.Fatal("identity not created")
	}
}

func TestBindEmailVerifyEnforcesLimitAtomically(t *testing.T) {
	service := newRegisterService(t)
	identities := service.Identities.(*fakeIdentities)
	identities.byProviderID = map[string]*model.Identity{
		"a@gmail.com": {UserID: 42, Provider: model.LoginMethodOtherMail, ProviderID: "a@gmail.com"},
		"b@gmail.com": {UserID: 42, Provider: model.LoginMethodOtherMail, ProviderID: "b@gmail.com"},
	}
	bindTickets := service.BindTicket.(*fakeBindTicketStore)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	if err := bindTickets.SaveBindTicket(context.Background(), "be_xxx", BindTicketPayload{Email: "c@gmail.com", UserID: 42}, time.Minute); err != nil {
		t.Fatalf("save bind ticket: %v", err)
	}
	if err := codes.SaveVerificationCode(context.Background(), string(mailer.VerificationPurposeBindEmail), "c@gmail.com", "123456", time.Minute); err != nil {
		t.Fatalf("save code: %v", err)
	}
	_, err := service.BindEmailVerify(context.Background(), BindEmailVerifyInput{UserID: 42, BindTicket: "be_xxx", Code: "123456"})
	assertKind(t, err, KindConflict, errcode.CodeIdentityLimitReached)
}

func TestBindEmailVerifyRejectsWrongCode(t *testing.T) {
	service := newRegisterService(t)
	bindTickets := service.BindTicket.(*fakeBindTicketStore)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	if err := bindTickets.SaveBindTicket(context.Background(), "be_xxx", BindTicketPayload{Email: "extra@gmail.com", UserID: 42}, time.Minute); err != nil {
		t.Fatalf("save bind ticket: %v", err)
	}
	if err := codes.SaveVerificationCode(context.Background(), string(mailer.VerificationPurposeBindEmail), "extra@gmail.com", "123456", time.Minute); err != nil {
		t.Fatalf("save code: %v", err)
	}
	_, err := service.BindEmailVerify(context.Background(), BindEmailVerifyInput{UserID: 42, BindTicket: "be_xxx", Code: "000000"})
	assertKind(t, err, KindInvalidInput, errcode.CodeVerificationCodeWrong)
}

func TestBindEmailVerifyRejectsLoginEmail(t *testing.T) {
	service := newRegisterService(t)
	bindTickets := service.BindTicket.(*fakeBindTicketStore)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	if err := bindTickets.SaveBindTicket(context.Background(), "be_xxx", BindTicketPayload{Email: "user@njupt.edu.cn", UserID: 42}, time.Minute); err != nil {
		t.Fatalf("save bind ticket: %v", err)
	}
	if err := codes.SaveVerificationCode(context.Background(), string(mailer.VerificationPurposeBindEmail), "user@njupt.edu.cn", "123456", time.Minute); err != nil {
		t.Fatalf("save code: %v", err)
	}
	_, err := service.BindEmailVerify(context.Background(), BindEmailVerifyInput{UserID: 42, BindTicket: "be_xxx", Code: "123456"})
	assertKind(t, err, KindConflict, errcode.CodeIdentityOccupied)
}

func TestBindEmailVerifyRejectsForeignTicket(t *testing.T) {
	service := newRegisterService(t)
	bindTickets := service.BindTicket.(*fakeBindTicketStore)
	if err := bindTickets.SaveBindTicket(context.Background(), "be_xxx", BindTicketPayload{Email: "extra@gmail.com", UserID: 99}, time.Minute); err != nil {
		t.Fatalf("save bind ticket: %v", err)
	}
	_, err := service.BindEmailVerify(context.Background(), BindEmailVerifyInput{UserID: 42, BindTicket: "be_xxx", Code: "123456"})
	assertKind(t, err, KindInvalidToken, errcode.CodeBindTicketInvalid)
}

func TestChangePasswordRotatesCredentialAndRevokesSessions(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	tokens := service.Tokens.(*fakeTokens)
	previousVersion := users.byID[42].TokenVersion

	result, err := service.ChangePassword(context.Background(), ChangePasswordInput{UserID: 42, OldPassword: "secret", NewPassword: "brand-new-password"})
	if err != nil {
		t.Fatalf("ChangePassword returned error: %v", err)
	}
	if result.UserID != 42 {
		t.Fatalf("result = %+v, want user 42", result)
	}
	if users.byID[42].TokenVersion != previousVersion+1 {
		t.Fatalf("token version = %d, want %d", users.byID[42].TokenVersion, previousVersion+1)
	}
	if service.Passwords.VerifyPassword(context.Background(), "brand-new-password", users.byID[42].PasswordHash) != nil {
		t.Fatal("new password does not verify against stored hash")
	}
	if len(tokens.revokedUsers) != 1 || tokens.revokedUsers[0] != 42 {
		t.Fatalf("revoked users = %#v, want all sessions of user 42 revoked", tokens.revokedUsers)
	}
}

func TestChangePasswordRejectsWrongOldSameNewAndShortNew(t *testing.T) {
	service := newRegisterService(t)

	_, err := service.ChangePassword(context.Background(), ChangePasswordInput{UserID: 42, OldPassword: "wrong", NewPassword: "brand-new-password"})
	assertKind(t, err, KindPasswordInvalid, errcode.CodePasswordInvalid)

	_, err = service.ChangePassword(context.Background(), ChangePasswordInput{UserID: 42, OldPassword: "longpassword", NewPassword: "longpassword"})
	assertKind(t, err, KindValidationFailed, errcode.CodePasswordUnchanged)

	_, err = service.ChangePassword(context.Background(), ChangePasswordInput{UserID: 42, OldPassword: "secret", NewPassword: "short"})
	assertKind(t, err, KindValidationFailed, errcode.CodePasswordTooShort)
}

func TestResetPasswordConsumesCodeAndRevokesSessions(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	tokens := service.Tokens.(*fakeTokens)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	resetPurpose := string(mailer.VerificationPurposeResetPassword)
	if err := codes.SaveVerificationCode(context.Background(), resetPurpose, "user@njupt.edu.cn", "123456", time.Minute); err != nil {
		t.Fatalf("save code: %v", err)
	}

	_, err := service.ResetPassword(context.Background(), ResetPasswordInput{Email: "user@njupt.edu.cn", Code: "123456", Password: "brand-new-password"})
	if err != nil {
		t.Fatalf("ResetPassword returned error: %v", err)
	}
	if service.Passwords.VerifyPassword(context.Background(), "brand-new-password", users.byID[42].PasswordHash) != nil {
		t.Fatal("new password does not verify against stored hash")
	}
	if len(tokens.revokedUsers) != 1 || tokens.revokedUsers[0] != 42 {
		t.Fatalf("revoked users = %#v, want all sessions of user 42 revoked", tokens.revokedUsers)
	}
	if _, ok := codes.codes[codeKey(resetPurpose, "user@njupt.edu.cn")]; ok {
		t.Fatal("verification code was not consumed")
	}
}

func TestResetPasswordRejectsUnchangedPassword(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	hash, err := service.Passwords.HashPassword(context.Background(), "longpassword")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	users.byID[42].PasswordHash = hash
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	if saveErr := codes.SaveVerificationCode(context.Background(), string(mailer.VerificationPurposeResetPassword), "user@njupt.edu.cn", "123456", time.Minute); saveErr != nil {
		t.Fatalf("save code: %v", saveErr)
	}
	_, err = service.ResetPassword(context.Background(), ResetPasswordInput{Email: "user@njupt.edu.cn", Code: "123456", Password: "longpassword"})
	assertKind(t, err, KindValidationFailed, errcode.CodePasswordUnchanged)
}

func TestResetPasswordShortPasswordDoesNotConsumeCode(t *testing.T) {
	service := newRegisterService(t)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	resetPurpose := string(mailer.VerificationPurposeResetPassword)
	if err := codes.SaveVerificationCode(context.Background(), resetPurpose, "user@njupt.edu.cn", "123456", time.Minute); err != nil {
		t.Fatalf("save code: %v", err)
	}
	_, err := service.ResetPassword(context.Background(), ResetPasswordInput{Email: "user@njupt.edu.cn", Code: "123456", Password: "short"})
	assertKind(t, err, KindValidationFailed, errcode.CodePasswordTooShort)
	if _, ok := codes.codes[codeKey(resetPurpose, "user@njupt.edu.cn")]; !ok {
		t.Fatal("verification code was consumed by rejected short password")
	}
}

// Login counts failures under "user:<id>" once the account is known, so a reset
// that only cleared "identifier:<email>" left a locked-out user locked for the
// rest of the window — defeating the recovery path they just completed.
func TestResetPasswordClearsUserScopedLockout(t *testing.T) {
	service := newRegisterService(t)
	failures := &fakeFailures{counts: map[string]int{}, retry: time.Minute}
	service.Failures = failures
	for range 10 {
		if _, err := failures.RecordFailure(context.Background(), "user:42"); err != nil {
			t.Fatalf("RecordFailure returned error: %v", err)
		}
	}
	if locked, _, _ := failures.IsLocked(context.Background(), "user:42"); !locked {
		t.Fatal("precondition: account should be locked after 10 failures")
	}
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	if err := codes.SaveVerificationCode(context.Background(), string(mailer.VerificationPurposeResetPassword), "user@njupt.edu.cn", "123456", time.Minute); err != nil {
		t.Fatalf("save code: %v", err)
	}

	if _, err := service.ResetPassword(context.Background(), ResetPasswordInput{Email: "user@njupt.edu.cn", Code: "123456", Password: "brand-new-password"}); err != nil {
		t.Fatalf("ResetPassword returned error: %v", err)
	}
	if locked, _, _ := failures.IsLocked(context.Background(), "user:42"); locked {
		t.Fatalf("account still locked after reset; cleared keys = %#v", failures.resets)
	}
	if !slices.Contains(failures.resets, "identifier:user@njupt.edu.cn") {
		t.Errorf("reset keys = %#v, want the identifier-scoped counter cleared too", failures.resets)
	}
}

func TestChangePasswordClearsUserScopedLockout(t *testing.T) {
	service := newRegisterService(t)
	failures := &fakeFailures{counts: map[string]int{}, retry: time.Minute}
	service.Failures = failures
	for range 10 {
		if _, err := failures.RecordFailure(context.Background(), "user:42"); err != nil {
			t.Fatalf("RecordFailure returned error: %v", err)
		}
	}

	if _, err := service.ChangePassword(context.Background(), ChangePasswordInput{UserID: 42, OldPassword: "secret", NewPassword: "brand-new-password"}); err != nil {
		t.Fatalf("ChangePassword returned error: %v", err)
	}
	if locked, _, _ := failures.IsLocked(context.Background(), "user:42"); locked {
		t.Fatalf("account still locked after change; cleared keys = %#v", failures.resets)
	}
}

// A swallowed revocation failure reported success while live refresh tokens
// survived: token_version alone does not stop them, because the refresh flow
// never compares it.
func TestPasswordUpdateFailsWhenSessionRevocationFails(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	users.updatePasswordErr = errors.New("revoke sessions failed")
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	if err := codes.SaveVerificationCode(context.Background(), string(mailer.VerificationPurposeResetPassword), "user@njupt.edu.cn", "123456", time.Minute); err != nil {
		t.Fatalf("save code: %v", err)
	}

	_, err := service.ChangePassword(context.Background(), ChangePasswordInput{UserID: 42, OldPassword: "secret", NewPassword: "brand-new-password"})
	assertKind(t, err, KindInternal, errcode.CodeInternal)

	_, err = service.ResetPassword(context.Background(), ResetPasswordInput{Email: "user@njupt.edu.cn", Code: "123456", Password: "brand-new-password"})
	assertKind(t, err, KindInternal, errcode.CodeInternal)
}

func newRegisterService(t *testing.T) Service {
	t.Helper()
	clock := fixedClock{value: time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	passwords := auth.PasswordHasher{Random: repeatedReader(0x42)}
	hash, err := passwords.HashPassword(context.Background(), "secret")
	if err != nil {
		t.Fatalf("hash test password: %v", err)
	}
	user := testUserWithHash(42, "user@njupt.edu.cn", model.UserStateOnSAST, hash)
	tokens := newFakeTokens()
	users := &fakeUsers{
		byLogin: map[string]*model.User{user.LoginEmail: user},
		byID:    map[int64]*model.User{user.ID: user},
		tokens:  tokens,
	}
	client := &model.OAuthClient{ID: 1, ClientID: "builtin", ClientType: model.ClientTypeFirstParty, IsActive: boolPtr(true), Scopes: model.StringArray(sessionScopes)}
	clients := &fakeClients{byClientID: map[string]*model.OAuthClient{client.ClientID: client}}
	return Service{
		Users:            users,
		Clients:          clients,
		Tokens:           tokens,
		Audit:            &fakeAudit{},
		Identities:       &fakeIdentities{},
		Limiter:          &fakeLimiter{},
		Mailer:           &fakeMailer{},
		VerificationCode: &fakeVerificationCodeStore{},
		RegisterTicket:   &fakeRegisterTicketStore{},
		BindTicket:       &fakeBindTicketStore{},
		InternalClientID: "builtin",
		JWT:              &auth.JWTManager{Issuer: "issuer", Audience: []string{"audience"}, Active: auth.JWTKeyPair{KID: "active", Private: key}, Clock: clock},
		RefreshTokens:    &auth.RefreshTokenManager{Random: rand.Reader, Secret: []byte("0123456789abcdef0123456789abcdef")},
		Passwords:        passwords,
		Clock:            clock,
		AccessTTL:        time.Hour,
		RefreshTTL:       24 * time.Hour,
	}
}

func newTestService(t *testing.T) (Service, *fakeUsers, *fakeClients, *fakeTokens, *fakeAudit, *fakeFailures) {
	t.Helper()
	clock := fixedClock{value: time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	passwords := auth.PasswordHasher{Random: repeatedReader(0x42)}
	hash, err := passwords.HashPassword(context.Background(), "secret")
	if err != nil {
		t.Fatalf("hash test password: %v", err)
	}
	user := testUserWithHash(42, "user@njupt.edu.cn", model.UserStateOnSAST, hash)
	client := &model.OAuthClient{ID: 1, ClientID: "builtin", ClientType: model.ClientTypeFirstParty, IsActive: boolPtr(true), Scopes: model.StringArray(sessionScopes)}
	clients := &fakeClients{byClientID: map[string]*model.OAuthClient{client.ClientID: client}}
	tokens := newFakeTokens()
	users := &fakeUsers{
		byLogin: map[string]*model.User{user.LoginEmail: user, "alias@sast.fun": user},
		byID:    map[int64]*model.User{user.ID: user},
		tokens:  tokens,
	}
	audit := &fakeAudit{}
	failures := &fakeFailures{}
	return Service{
		Users:            users,
		Clients:          clients,
		Tokens:           tokens,
		Audit:            audit,
		Limiter:          &fakeLimiter{},
		Failures:         failures,
		InternalClientID: "builtin",
		JWT:              &auth.JWTManager{Issuer: "issuer", Audience: []string{"audience"}, Active: auth.JWTKeyPair{KID: "active", Private: key}, Clock: clock},
		RefreshTokens:    &auth.RefreshTokenManager{Random: rand.Reader, Secret: []byte("0123456789abcdef0123456789abcdef")},
		Passwords:        passwords,
		Clock:            clock,
		AccessTTL:        time.Hour,
		RefreshTTL:       24 * time.Hour,
	}, users, clients, tokens, audit, failures
}

func testUser(t *testing.T, id int64, email string, state model.UserState) *model.User {
	t.Helper()
	passwords := auth.PasswordHasher{Random: repeatedReader(0x42)}
	hash, err := passwords.HashPassword(context.Background(), "secret")
	if err != nil {
		t.Fatalf("hash test password: %v", err)
	}
	return testUserWithHash(id, email, state, hash)
}

func testUserWithHash(id int64, email string, state model.UserState, passwordHash string) *model.User {
	nickname := "pt"
	department := model.DepartmentSoftware
	return &model.User{
		ID: id, Role: model.UserRoleMember, Name: "SASTer", PasswordHash: passwordHash,
		StudentID: "B20000000", State: state, EmailType: model.EmailTypeNJUpt,
		LoginEmail: email, College: model.CollegeComputerSoftwareCybersecurity,
		Major: "Software", TokenVersion: 7,
		Profile: &model.Profile{UserID: id, Nickname: &nickname, Department: &department},
		Identities: []model.Identity{{
			ID: 11, UserID: id, Provider: model.LoginMethodGitHub, ProviderID: "145339646",
			IdentityData: model.JSONB(`{"login":"pt"}`),
		}},
	}
}

func boolPtr(value bool) *bool { return &value }

func loginForLogout(t *testing.T, service *Service) (*LoginResult, *auth.TokenClaims) {
	t.Helper()
	login, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	claims, err := service.JWT.VerifyAccessToken(login.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken returned error: %v", err)
	}
	return login, claims
}

func assertKind(t *testing.T, err error, kind Kind, code int) {
	t.Helper()
	var serviceErr *Error
	if !errors.As(err, &serviceErr) {
		t.Fatalf("error = %v, want *Error", err)
	}
	if serviceErr.Kind != kind || serviceErr.Code != code {
		t.Fatalf("error = %+v, want kind=%s code=%d", serviceErr, kind, code)
	}
}

func lastErrCode(audit *fakeAudit) int {
	if len(audit.entries) == 0 || audit.entries[len(audit.entries)-1].ErrCode == nil {
		return 0
	}
	return *audit.entries[len(audit.entries)-1].ErrCode
}

// A wrong code used to consume the stored value, so one bad guess burned the
// valid code for every flow that verifies one.
func TestWrongVerificationCodeDoesNotBurnTheCode(t *testing.T) {
	tests := []struct {
		name   string
		save   func(*fakeVerificationCodeStore)
		submit func(Service, string) error
	}{
		{
			name: "register verify-code",
			save: func(codes *fakeVerificationCodeStore) {
				codes.codes = map[string]string{codeKey(string(mailer.VerificationPurposeRegister), "new@sast.fun"): "123456"}
			},
			submit: func(service Service, code string) error {
				_, err := service.VerifyRegisterCode(context.Background(), VerifyRegisterCodeInput{Email: "new@sast.fun", Code: code})
				return err
			},
		},
		{
			name: "reset password",
			save: func(codes *fakeVerificationCodeStore) {
				codes.codes = map[string]string{codeKey(string(mailer.VerificationPurposeResetPassword), "user@njupt.edu.cn"): "123456"}
			},
			submit: func(service Service, code string) error {
				_, err := service.ResetPassword(context.Background(), ResetPasswordInput{
					Email:    "user@njupt.edu.cn",
					Code:     code,
					Password: "brand-new-password",
				})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newRegisterService(t)
			codes := service.VerificationCode.(*fakeVerificationCodeStore)
			test.save(codes)

			err := test.submit(service, "000000")
			assertKind(t, err, KindInvalidInput, errcode.CodeVerificationCodeWrong)

			// The valid code must still work on the next try.
			if err := test.submit(service, "123456"); err != nil {
				t.Fatalf("correct code rejected after one wrong guess: %v", err)
			}
		})
	}
}

// Once the store reports the attempt budget spent, the caller must surface the
// expired outcome rather than an endless "wrong code".
func TestExhaustedVerificationAttemptsReportExpired(t *testing.T) {
	service := newRegisterService(t)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	codes.attemptCap = 2
	codes.codes = map[string]string{codeKey(string(mailer.VerificationPurposeRegister), "new@sast.fun"): "123456"}

	_, err := service.VerifyRegisterCode(context.Background(), VerifyRegisterCodeInput{Email: "new@sast.fun", Code: "000000"})
	assertKind(t, err, KindInvalidInput, errcode.CodeVerificationCodeWrong)

	_, err = service.VerifyRegisterCode(context.Background(), VerifyRegisterCodeInput{Email: "new@sast.fun", Code: "000000"})
	assertKind(t, err, KindInvalidInput, errcode.CodeVerificationCodeExpired)

	_, err = service.VerifyRegisterCode(context.Background(), VerifyRegisterCodeInput{Email: "new@sast.fun", Code: "123456"})
	assertKind(t, err, KindInvalidInput, errcode.CodeVerificationCodeExpired)
}

// BindEmailVerify consumed the Bind-Ticket before checking the code, so a typo
// cost the user their ticket and forced a new send-code round trip.
func TestBindEmailVerifyKeepsTicketOnWrongCode(t *testing.T) {
	service := newRegisterService(t)
	tickets := service.BindTicket.(*fakeBindTicketStore)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	if err := tickets.SaveBindTicket(context.Background(), "be_abc", BindTicketPayload{UserID: 42, Email: "bind@qq.com"}, time.Minute); err != nil {
		t.Fatalf("SaveBindTicket() error = %v", err)
	}
	codes.codes = map[string]string{codeKey(string(mailer.VerificationPurposeBindEmail), "bind@qq.com"): "123456"}

	_, err := service.BindEmailVerify(context.Background(), BindEmailVerifyInput{UserID: 42, BindTicket: "be_abc", Code: "000000"})
	assertKind(t, err, KindInvalidInput, errcode.CodeVerificationCodeWrong)
	if _, ok := tickets.tickets["be_abc"]; !ok {
		t.Fatal("Bind-Ticket was consumed by a wrong verification code")
	}

	result, err := service.BindEmailVerify(context.Background(), BindEmailVerifyInput{UserID: 42, BindTicket: "be_abc", Code: "123456"})
	if err != nil {
		t.Fatalf("BindEmailVerify() after retry error = %v", err)
	}
	if result.Email != "bind@qq.com" {
		t.Fatalf("result = %+v, want bind@qq.com", result)
	}
	// The successful bind spends the ticket, so it cannot be replayed.
	if _, ok := tickets.tickets["be_abc"]; ok {
		t.Fatal("Bind-Ticket survived a successful bind")
	}
}

// A ticket that does not belong to the caller must be rejected without being
// spent, so the rightful owner can still use it.
func TestBindEmailVerifyKeepsTicketOnOwnerMismatch(t *testing.T) {
	service := newRegisterService(t)
	tickets := service.BindTicket.(*fakeBindTicketStore)
	if err := tickets.SaveBindTicket(context.Background(), "be_abc", BindTicketPayload{UserID: 42, Email: "bind@qq.com"}, time.Minute); err != nil {
		t.Fatalf("SaveBindTicket() error = %v", err)
	}

	_, err := service.BindEmailVerify(context.Background(), BindEmailVerifyInput{UserID: 99, BindTicket: "be_abc", Code: "123456"})
	assertKind(t, err, KindInvalidToken, errcode.CodeBindTicketInvalid)
	if _, ok := tickets.tickets["be_abc"]; !ok {
		t.Fatal("Bind-Ticket was consumed by a request from the wrong user")
	}
}

// Register consumed the ticket before the uniqueness checks, so a taken student
// ID burned it too.
func TestRegisterKeepsTicketWhenStudentIDOccupied(t *testing.T) {
	service := newRegisterService(t)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	users := service.Users.(*fakeUsers)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_xxx", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("SaveRegisterTicket() error = %v", err)
	}
	occupied := users.byID[42].StudentID

	_, err := service.Register(context.Background(), RegisterInput{
		RegisterTicket: "reg_xxx",
		Password:       "newpassword",
		Name:           "Dup",
		StudentID:      occupied,
		PhoneNumber:    "13800138000",
		QQNumber:       "10000",
		College:        string(model.CollegeOther),
		Major:          "CS",
	})
	assertKind(t, err, KindConflict, errcode.CodeStudentIDOccupied)
	if _, ok := tickets.tickets["reg_xxx"]; !ok {
		t.Fatal("Register-Ticket was consumed by an occupied student ID")
	}

	// The corrected retry must succeed on the same ticket.
	if _, err := service.Register(context.Background(), RegisterInput{
		RegisterTicket: "reg_xxx",
		Password:       "newpassword",
		Name:           "Fixed",
		StudentID:      "B24040099",
		PhoneNumber:    "13800138000",
		QQNumber:       "10000",
		College:        string(model.CollegeOther),
		Major:          "CS",
	}); err != nil {
		t.Fatalf("Register() retry error = %v", err)
	}
	if _, ok := tickets.tickets["reg_xxx"]; ok {
		t.Fatal("Register-Ticket survived a successful registration")
	}
}

// If the ticket cannot be issued, the already-matched code must be discarded so
// it cannot be replayed by a retry.
func TestVerifyRegisterCodeDiscardsCodeWhenTicketSaveFails(t *testing.T) {
	service := newRegisterService(t)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	purpose := string(mailer.VerificationPurposeRegister)
	codes.codes = map[string]string{codeKey(purpose, "new@sast.fun"): "123456"}
	service.RegisterTicket = &fakeRegisterTicketStore{err: errors.New("redis unavailable")}

	_, err := service.VerifyRegisterCode(context.Background(), VerifyRegisterCodeInput{Email: "new@sast.fun", Code: "123456"})
	assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	if !slices.Contains(codes.discarded, codeKey(purpose, "new@sast.fun")) {
		t.Fatalf("discarded = %#v, want the consumed code dropped", codes.discarded)
	}
}

// The "user" table has two unique constraints, and the insert path used to map
// every violation to 40901, telling a user whose student ID clashed that their
// email was taken — pointing them at the wrong field.
func TestRegisterMapsUniqueViolationToTheCollidingField(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		wantCode   int
		wantKind   Kind
	}{
		{name: "student id", constraint: userStudentIDConstraint, wantCode: errcode.CodeStudentIDOccupied, wantKind: KindConflict},
		{name: "login email", constraint: userLoginEmailConstraint, wantCode: errcode.CodeEmailAlreadyRegistered, wantKind: KindConflict},
		{name: "unmapped constraint", constraint: "user_some_future_key", wantCode: errcode.CodeConflict, wantKind: KindConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newRegisterService(t)
			users := service.Users.(*fakeUsers)
			tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
			if err := tickets.SaveRegisterTicket(context.Background(), "reg_x", "new@sast.fun", time.Minute); err != nil {
				t.Fatalf("SaveRegisterTicket() error = %v", err)
			}
			// Simulate losing the race between the pre-flight check and the insert.
			users.createErr = uniqueViolation(test.constraint)

			_, err := service.Register(context.Background(), validRegisterInput("reg_x", "B24040111"))
			assertKind(t, err, test.wantKind, test.wantCode)
		})
	}
}

// A conflict raised by the insert is a lost race, not a spent ticket: the user
// must be able to correct the field and retry without a new verification code.
func TestRegisterKeepsTicketWhenInsertRaces(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_x", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("SaveRegisterTicket() error = %v", err)
	}
	users.createErr = uniqueViolation(userStudentIDConstraint)

	_, err := service.Register(context.Background(), validRegisterInput("reg_x", "B24040111"))
	assertKind(t, err, KindConflict, errcode.CodeStudentIDOccupied)
	if _, ok := tickets.tickets["reg_x"]; !ok {
		t.Fatal("Register-Ticket was consumed by a losing race; the user must re-request a code")
	}

	// The corrected retry succeeds on the same ticket and spends it.
	users.createErr = nil
	if _, err := service.Register(context.Background(), validRegisterInput("reg_x", "B24040222")); err != nil {
		t.Fatalf("Register() retry error = %v", err)
	}
	if _, ok := tickets.tickets["reg_x"]; ok {
		t.Fatal("Register-Ticket survived a successful registration")
	}
}

// A non-unique database failure must stay a 500 rather than being reported as a
// conflict the user could act on.
func TestRegisterReportsNonUniqueInsertFailureAsInternal(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_x", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("SaveRegisterTicket() error = %v", err)
	}
	users.createErr = errors.New("connection reset")

	_, err := service.Register(context.Background(), validRegisterInput("reg_x", "B24040111"))
	assertKind(t, err, KindInternal, errcode.CodeInternal)
}

func validRegisterInput(ticket, studentID string) RegisterInput {
	return RegisterInput{
		RegisterTicket: ticket,
		Password:       "newpassword",
		Name:           "pt",
		StudentID:      studentID,
		PhoneNumber:    "13800138000",
		QQNumber:       "10000",
		College:        string(model.CollegeOther),
		Major:          "CS",
	}
}

// Password verification queues behind a concurrency gate, so a cancelled caller
// gets an error that is not a password mismatch. Counting it as a failed attempt
// would let a client that disconnects mid-login drive its own account into the
// lockout window, and would fill the audit log with failures nobody made.
func TestLoginDoesNotCountAbandonedVerificationAsFailure(t *testing.T) {
	service, _, _, _, audit, failures := newTestService(t)
	service.Passwords = auth.PasswordHasher{Semaphore: make(chan struct{}, 1)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := service.Login(ctx, LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret", ClientIP: "127.0.0.1"})
	if err == nil {
		t.Fatal("Login() error = nil, want the abandoned request to fail")
	}
	assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	if len(failures.failures) != 0 {
		t.Fatalf("failures = %#v, want no failure recorded for an abandoned request", failures.failures)
	}
	for _, entry := range audit.entries {
		if entry.Action == "login" && entry.Success != nil && !*entry.Success {
			t.Fatal("abandoned login was audited as a failed attempt")
		}
	}
}

// The same rule for ChangePassword: an abandoned old-password check is not a
// wrong old password.
func TestChangePasswordDoesNotAuditAbandonedVerificationAsFailure(t *testing.T) {
	service, _, _, _, audit, _ := newTestService(t)
	service.Passwords = auth.PasswordHasher{Semaphore: make(chan struct{}, 1)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := service.ChangePassword(ctx, ChangePasswordInput{
		UserID:      42,
		OldPassword: "secret",
		NewPassword: "brand-new-password",
	})
	assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	for _, entry := range audit.entries {
		if entry.Action == "change_password" && entry.Success != nil && !*entry.Success {
			t.Fatal("abandoned change-password was audited as a wrong old password")
		}
	}
}

// Registration hashing is gated too; an abandoned hash is a 503, not a 500 that
// blames the server for a client that left.
func TestRegisterReportsAbandonedHashingAsDependencyUnavailable(t *testing.T) {
	service := newRegisterService(t)
	service.Passwords = auth.PasswordHasher{Semaphore: make(chan struct{}, 1)}
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_x", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("SaveRegisterTicket() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := service.Register(ctx, validRegisterInput("reg_x", "B24040111"))
	assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	// The ticket must survive: nothing was decided about this registration.
	if _, ok := tickets.tickets["reg_x"]; !ok {
		t.Fatal("Register-Ticket was consumed by an abandoned request")
	}
}
