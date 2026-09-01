package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"sync"
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

var (
	testCredentialsOnce sync.Once
	testPrivateKey      ed25519.PrivateKey
	testPasswordHash    string
	testCredentialsErr  error
)

// sharedTestCredentials computes the immutable, production-strength password
// hash and Ed25519 key once per package. The session fixtures are created over
// a hundred times; deriving an argon2id hash and generating an Ed25519 keypair
// for every fixture makes the package exceed Go's 10-minute timeout under -race
// and atomic coverage without improving test isolation. Tests still receive
// fresh services and mutable fakes; only these read-only cryptographic values
// are shared.
func sharedTestCredentials(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	testCredentialsOnce.Do(func() {
		_, testPrivateKey, testCredentialsErr = ed25519.GenerateKey(rand.Reader)
		if testCredentialsErr != nil {
			return
		}
		passwords := auth.PasswordHasher{Random: repeatedReader(0x42)}
		testPasswordHash, testCredentialsErr = passwords.HashPassword(context.Background(), "secret")
	})
	if testCredentialsErr != nil {
		t.Fatalf("initialize shared test credentials: %v", testCredentialsErr)
	}
	return testPrivateKey, testPasswordHash
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
	// rehashUpdates records UpdatePasswordHash calls, which the repository makes
	// only for rehash-on-login (no token_version bump, no revocation).
	rehashUpdates []int64
	// createErr forces CreateWithProfile to fail, for racing-insert scenarios the
	// in-memory maps cannot reproduce.
	createErr error
	// registeredIdentity records the third-party binding persisted alongside a
	// registration, so tests can assert the OAuth branch wrote one.
	registeredIdentity *model.Identity
	// otherMailIdentities holds provider_id -> user_id for other_mail identities,
	// so ExistsAsEmailAnywhere can mirror the cross-table uniqueness check.
	otherMailIdentities map[string]int64
	// updateProfileErr forces UpdateProfile to fail, for conflict scenarios the
	// in-memory maps cannot reproduce.
	updateProfileErr error
	profileUpdates   []repository.ProfileUpdate
}

func (f *fakeUsers) FindByLoginIdentifier(_ context.Context, identifier string) (*model.User, error) {
	return f.lookup(identifier)
}

func (f *fakeUsers) FindAuthUserByLoginIdentifier(_ context.Context, identifier string) (*model.User, error) {
	return f.lookup(identifier)
}

func (f *fakeUsers) lookup(identifier string) (*model.User, error) {
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

func (f *fakeUsers) FindProfileByID(_ context.Context, userID int64) (*model.User, error) {
	return f.FindByID(context.Background(), userID)
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

func (f *fakeUsers) FindAuthUserByID(_ context.Context, userID int64) (*model.User, error) {
	return f.FindByID(context.Background(), userID)
}

func (f *fakeUsers) FindAuthUserByLoginEmail(_ context.Context, email string) (*model.User, error) {
	return f.FindByLoginEmail(context.Background(), email)
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

func (f *fakeUsers) CreateRegistration(
	ctx context.Context,
	user *model.User,
	profile *model.Profile,
	pairFactory repository.TokenPairFactory,
) error {
	return f.CreateRegistrationWithIdentity(ctx, user, profile, nil, pairFactory)
}

func (f *fakeUsers) CreateRegistrationWithIdentity(
	ctx context.Context,
	user *model.User,
	profile *model.Profile,
	identity *model.Identity,
	pairFactory repository.TokenPairFactory,
) error {
	if err := f.CreateWithProfile(ctx, user, profile); err != nil {
		return err
	}
	if identity != nil {
		identity.UserID = user.ID
		f.registeredIdentity = identity
	}
	access, refresh, err := pairFactory(user)
	if err != nil {
		delete(f.byLogin, user.LoginEmail)
		delete(f.byID, user.ID)
		user.ID = 0
		return err
	}
	if f.tokens == nil {
		delete(f.byLogin, user.LoginEmail)
		delete(f.byID, user.ID)
		user.ID = 0
		return errors.New("token repository unavailable")
	}
	if err := f.tokens.CreatePair(ctx, access, refresh); err != nil {
		delete(f.byLogin, user.LoginEmail)
		delete(f.byID, user.ID)
		user.ID = 0
		return err
	}
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

// UpdatePasswordHash mirrors the repository's guarded in-place rehash write:
// the hash changes only if currentHash still matches (a concurrent password
// change/reset wins, and the rehash is skipped), and — unlike
// UpdatePasswordAndRevokeSessions — no session is revoked and token_version is
// untouched.
func (f *fakeUsers) UpdatePasswordHash(_ context.Context, userID int64, currentHash, passwordHash string) error {
	user, ok := f.byID[userID]
	if !ok {
		return repository.ErrNotFound
	}
	if user.PasswordHash != currentHash {
		return repository.ErrRehashSkipped
	}
	user.PasswordHash = passwordHash
	f.rehashUpdates = append(f.rehashUpdates, userID)
	return nil
}

// UpdateProfile mirrors the repository's partial update: only non-nil fields are
// applied, and the reloaded aggregate is returned.
func (f *fakeUsers) UpdateProfile(_ context.Context, userID int64, update repository.ProfileUpdate) (*model.User, error) {
	if f.updateProfileErr != nil {
		return nil, f.updateProfileErr
	}
	user, ok := f.byID[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	f.profileUpdates = append(f.profileUpdates, update)
	applyString(&user.Name, update.Name)
	applyString(&user.PhoneNumber, update.PhoneNumber)
	applyString(&user.QQNumber, update.QQNumber)
	applyString(&user.StudentID, update.StudentID)
	applyString(&user.Major, update.Major)
	if update.College != nil {
		user.College = *update.College
	}
	if user.Profile == nil {
		user.Profile = &model.Profile{UserID: userID}
	}
	applyNullable(&user.Profile.Nickname, update.Nickname)
	applyNullable(&user.Profile.Intro, update.Intro)
	applyNullable(&user.Profile.Email, update.Email)
	applyNullable(&user.Profile.Avatar, update.Avatar)
	applyNullable(&user.Profile.BlogURL, update.BlogURL)
	applyNullable(&user.Profile.GitHubURL, update.GitHubURL)
	if update.Department != nil {
		if *update.Department == "" {
			user.Profile.Department = nil
		} else {
			department := *update.Department
			user.Profile.Department = &department
		}
	}
	return user, nil
}

func applyString(target *string, value *string) {
	if value != nil {
		*target = *value
	}
}

func applyNullable(target **string, value *string) {
	if value == nil {
		return
	}
	if *value == "" {
		*target = nil
		return
	}
	assigned := *value
	*target = &assigned
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

func (f *fakeClients) FindActiveInternalClient(_ context.Context, clientID string) (*model.OAuthClient, error) {
	return f.FindActiveByClientID(context.Background(), clientID)
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
	createErr           error
	revokeErr           error
	// auditEntries records the outbox rows enqueued with token pairs/rotations,
	// the async replacement for the synchronous success audit.
	auditEntries []*model.AuditLog
}

func newFakeTokens() *fakeTokens {
	return &fakeTokens{accessByJTI: map[string]*model.OAuthAccessToken{}, refreshByHash: map[string]*model.OAuthRefreshToken{}}
}

func (f *fakeTokens) CreatePair(_ context.Context, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.createdAccess = access
	f.createdRefresh = refresh
	f.accessByJTI[access.TokenID] = access
	f.refreshByHash[refresh.TokenHash] = refresh
	return nil
}

func (f *fakeTokens) CreatePairWithAudit(_ context.Context, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken, outbox *model.AuditLog) error {
	if err := f.CreatePair(context.Background(), access, refresh); err != nil {
		return err
	}
	f.auditEntries = append(f.auditEntries, outbox)
	return nil
}

func (f *fakeTokens) RotateRefreshTokenWithAudit(_ context.Context, familyID string, currentHash string, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken, outbox *model.AuditLog) (time.Time, error) {
	origin, err := f.RotateRefreshToken(context.Background(), familyID, currentHash, access, refresh)
	if err != nil {
		return time.Time{}, err
	}
	f.auditEntries = append(f.auditEntries, outbox)
	return origin, nil
}

func (f *fakeTokens) RotateRefreshToken(_ context.Context, familyID string, currentHash string, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) (time.Time, error) {
	if f.rotateErr != nil {
		if errors.Is(f.rotateErr, repository.ErrTokenReplay) {
			if current := f.refreshByHash[currentHash]; current != nil {
				f.revokedFamilies = append(f.revokedFamilies, current.FamilyID)
			}
		}
		return time.Time{}, f.rotateErr
	}
	current, ok := f.refreshByHash[currentHash]
	if !ok {
		return time.Time{}, repository.ErrNotFound
	}
	if current.FamilyID != familyID {
		return time.Time{}, repository.ErrInvalidArgument
	}
	now := time.Now().UTC()
	current.RevokedAt = &now
	f.rotatedAccess = access
	f.rotatedRefresh = refresh
	f.accessByJTI[access.TokenID] = access
	f.refreshByHash[refresh.TokenHash] = refresh
	return current.CreatedAt, nil
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
	jtis []string
	err  error
}

func (f *fakeBlacklist) DeleteAuthStates(_ context.Context, jtis []string) error {
	if f.err != nil {
		return f.err
	}
	f.jtis = jtis
	return nil
}

type fakeForgotPasswordDispatcher struct {
	jobs     []ForgotPasswordJob
	accepted bool
}

func (f *fakeForgotPasswordDispatcher) EnqueueForgotPassword(job ForgotPasswordJob) bool {
	f.jobs = append(f.jobs, job)
	return f.accepted
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
	// users lets DeleteIdentityGuardingLoginMethod read the account's login
	// email when deciding whether an identity is its last way in.
	users        *fakeUsers
	err          error
	createErr    error
	deleteErr    error
	deleted      []int64
	beforeDelete func()
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

func (f *fakeIdentities) ListByUser(_ context.Context, userID int64) ([]model.Identity, error) {
	if f.err != nil {
		return nil, f.err
	}
	identities := make([]model.Identity, 0, len(f.byProviderID))
	for _, identity := range f.byProviderID {
		if identity.UserID == userID {
			identities = append(identities, *identity)
		}
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].ID < identities[j].ID })
	return identities, nil
}

func (f *fakeIdentities) FindByIDAndUser(_ context.Context, identityID, userID int64) (*model.Identity, error) {
	if f.err != nil {
		return nil, f.err
	}
	for _, identity := range f.byProviderID {
		if identity.ID == identityID && identity.UserID == userID {
			return identity, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (f *fakeIdentities) DeleteByIDAndUser(_ context.Context, identityID, userID int64) error {
	if f.beforeDelete != nil {
		f.beforeDelete()
	}
	if f.deleteErr != nil {
		return f.deleteErr
	}
	for providerID, identity := range f.byProviderID {
		if identity.ID == identityID && identity.UserID == userID {
			delete(f.byProviderID, providerID)
			f.deleted = append(f.deleted, identityID)
			return nil
		}
	}
	return repository.ErrNotFound
}

func (f *fakeIdentities) DeleteIdentityGuardingLoginMethod(_ context.Context, identityID, userID int64) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	hasLoginEmail := false
	if f.users != nil {
		if user, ok := f.users.byID[userID]; ok && strings.TrimSpace(user.LoginEmail) != "" {
			hasLoginEmail = true
		}
	}
	remaining := int64(0)
	for _, identity := range f.byProviderID {
		if identity.ID != identityID && identity.UserID == userID {
			remaining++
		}
	}
	if !hasLoginEmail && remaining == 0 {
		return repository.ErrLastLoginMethod
	}
	return f.DeleteByIDAndUser(context.Background(), identityID, userID)
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
	service, users, _, tokens, _, failures := newTestService(t)
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
	if len(tokens.auditEntries) != 1 || tokens.auditEntries[0].Action != "login" || tokens.auditEntries[0].Success == nil || !*tokens.auditEntries[0].Success {
		t.Fatalf("audit outboxes = %#v, want successful login audit enqueued", tokens.auditEntries)
	}
	if got := service.Limiter.(*fakeLimiter).calls[0]; got != "login:127.0.0.1" {
		t.Fatalf("limiter subject = %q, want client IP", got)
	}
	detail := string(tokens.auditEntries[0].Detail)
	if !strings.Contains(detail, `"method":"password"`) || strings.Contains(detail, "identifier") {
		t.Fatalf("audit detail = %s, want method only", detail)
	}
}

// A successful login upgrades a stale hash to the configured parameters in place
// (rehash-on-login), so a KDF work-factor change reaches existing accounts on
// their next login instead of verifying at the old cost forever. The rehash must
// not revoke the session being created: the write is UpdatePasswordHash, not
// UpdatePasswordAndRevokeSessions.
func TestLoginRehashesStalePassword(t *testing.T) {
	service, users, _, _, _, _ := newTestService(t)
	// Configure the service for 8 MiB; the stored hash carries 16 MiB, exactly the
	// shape of a work-factor change reaching an existing account.
	service.Passwords = auth.PasswordHasher{Random: repeatedReader(0x42), Argon2Time: 1, Argon2Memory: 8192, Argon2Threads: 1}
	stale, err := (auth.PasswordHasher{Random: repeatedReader(0x42), Argon2Time: 1, Argon2Memory: 16384, Argon2Threads: 1}).HashPassword(context.Background(), "secret")
	if err != nil {
		t.Fatalf("hash stale password: %v", err)
	}
	users.byID[42].PasswordHash = stale

	if _, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"}); err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if len(users.rehashUpdates) != 1 || users.rehashUpdates[0] != 42 {
		t.Fatalf("rehash updates = %#v, want user 42", users.rehashUpdates)
	}
	if len(users.passwordUpdates) != 0 {
		t.Fatalf("password-update+revoke calls = %#v, want none (rehash must not revoke sessions)", users.passwordUpdates)
	}
	if users.byID[42].PasswordHash == stale {
		t.Fatal("stored hash was not upgraded")
	}
	if parts := strings.Split(users.byID[42].PasswordHash, "$"); len(parts) != 6 || parts[0] != "argon2id-v1" || parts[1] != "1" || parts[2] != "8192" {
		t.Fatalf("rehashed hash = %q, want argon2id m=8192", users.byID[42].PasswordHash)
	}
}

// A login whose stored hash already matches the configured parameters must not
// rewrite the hash: the extra write is pure overhead on the hot path.
func TestLoginDoesNotRehashWhenParametersMatch(t *testing.T) {
	service, users, _, _, _, _ := newTestService(t)
	// newTestService hashes "secret" with the same bare hasher Login uses, so the
	// parameters match by construction.
	if _, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"}); err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if len(users.rehashUpdates) != 0 {
		t.Fatalf("rehash updates = %#v, want none when parameters match", users.rehashUpdates)
	}
}

func TestLoginFailuresAreTypedAndCounted(t *testing.T) {
	service, _, _, _, audit, failures := newTestService(t)
	_, err := service.Login(context.Background(), LoginInput{Identifier: "missing@sast.fun", Password: "secret"})
	// An unknown identifier answers exactly like a wrong password (audit-fix #7):
	// distinguishing them on the wire hands anyone a registered-email oracle.
	assertKind(t, err, KindLoginFailed, errcode.CodePasswordInvalid)
	if len(failures.failures) != 1 || failures.failures[0] != "identifier:missing@sast.fun" {
		t.Fatalf("failures = %#v, want unknown bucket counted", failures.failures)
	}

	_, err = service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "wrong"})
	assertKind(t, err, KindLoginFailed, errcode.CodePasswordInvalid)
	if len(failures.failures) != 2 || failures.failures[1] != "user:42" {
		t.Fatalf("failures = %#v, want known user bucket", failures.failures)
	}
	// One audit code for both legs; the reason field keeps the distinction.
	if got := lastErrCode(audit); got != errcode.CodePasswordInvalid {
		t.Fatalf("audit err code = %d, want %d", got, errcode.CodePasswordInvalid)
	}
}

func TestServiceErrorsMatchSentinels(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)

	// An unknown identifier now answers with the login-failed sentinel (audit-fix
	// #7): the wire must not distinguish the two, or a login attempt becomes a
	// registered-email oracle.
	_, err := service.Login(context.Background(), LoginInput{Identifier: "missing@sast.fun", Password: "secret"})
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("unknown identifier: errors.Is(err, ErrLoginFailed) = false, err=%v", err)
	}

	_, err = service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "wrong"})
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("password invalid: errors.Is(err, ErrLoginFailed) = false, err=%v", err)
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
	assertKind(t, err, KindLoginFailed, errcode.CodePasswordInvalid)
}

func TestLoginRejectsDeletedAndInvalidClient(t *testing.T) {
	service, _, clients, _, _, failures := newTestService(t)
	service.Users.(*fakeUsers).byLogin["deleted@sast.fun"] = testUser(t, 99, "deleted@sast.fun", model.UserStateDeleted)
	_, err := service.Login(context.Background(), LoginInput{Identifier: "deleted@sast.fun", Password: "secret"})
	// A deleted account answers like any other failed login, so probing cannot
	// tell "never registered" from "closed" (audit-fix #7 follow-up).
	assertKind(t, err, KindLoginFailed, errcode.CodePasswordInvalid)
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
	service, _, _, tokens, _, _ := newTestService(t)
	_, err := service.Login(context.Background(), LoginInput{Identifier: "alias@sast.fun", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	detail := string(tokens.auditEntries[len(tokens.auditEntries)-1].Detail)
	if !strings.Contains(detail, `"method":"other_mail"`) || strings.Contains(detail, "identifier") {
		t.Fatalf("audit detail = %s, want other_mail method only", detail)
	}
}

// The success audit rides the token transaction, so a failure inside that
// transaction rolls the pair back atomically — there is no half-issued session
// to compensate, because the audit row commits with the pair or not at all.
func TestLoginTokenPairFailureIsAtomic(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)
	tokens.createErr = errors.New("pair down")
	_, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	assertKind(t, err, KindInternal, errcode.CodeInternal)
	if tokens.createdAccess != nil || len(tokens.revokedFamilies) != 0 {
		t.Fatalf("created=%+v revoked=%#v, want nothing created and nothing to compensate", tokens.createdAccess, tokens.revokedFamilies)
	}
}

// A lost counter reset leaves a stale count that expires with its own 15min
// window. Revoking the pair instead would make every login fail for the whole
// duration of a Redis outage, so the session is kept and the audit still runs.
func TestLoginKeepsSessionWhenFailureResetUnavailable(t *testing.T) {
	service, _, _, tokens, _, failures := newTestService(t)
	failures.resetErr = errors.New("redis down")
	result, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if result.AccessToken == "" || len(tokens.revokedFamilies) != 0 {
		t.Fatalf("result=%+v revoked=%#v, want issued pair with no compensation", result, tokens.revokedFamilies)
	}
	if len(tokens.auditEntries) != 1 || tokens.auditEntries[0].Success == nil || !*tokens.auditEntries[0].Success {
		t.Fatalf("audit outboxes = %#v, want successful login audit enqueued", tokens.auditEntries)
	}
}

// With the audit folded into the token transaction there is no post-issue step
// left to compensate; a cancelled request aborts before the pair exists.
func TestLoginAbortsWhenRequestCancelled(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)
	// A semaphore makes the hasher honour a cancelled context at the queue.
	service.Passwords = auth.PasswordHasher{Semaphore: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := service.Login(ctx, LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	if tokens.createdAccess != nil || len(tokens.revokedFamilies) != 0 {
		t.Fatalf("created=%+v revoked=%#v, want nothing on a cancelled request", tokens.createdAccess, tokens.revokedFamilies)
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
	devices := &fakeDevices{}
	service = withDevices(service, devices)
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
	// Rotation failure cuts the family; the device record must die with it, or
	// the list keeps showing a session that can no longer authenticate.
	if len(devices.removed) != 1 || devices.removed[0] != tokens.createdRefresh.FamilyID {
		t.Fatalf("removed = %#v, want the replayed family's device record", devices.removed)
	}
}

func TestRefreshWithinGraceReplayPreservesDeviceRecord(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)
	devices := &fakeDevices{}
	service = withDevices(service, devices)
	login, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	// A benign concurrent refresh: the winning rotation already cut this token,
	// but within the grace window the family is preserved. The fake returns the
	// sentinel without recording a family revoke, exactly like the repository
	// does for the within-grace case.
	tokens.rotateErr = repository.ErrTokenReplayWithinGrace
	_, err = service.Refresh(context.Background(), RefreshInput{RefreshToken: login.RefreshToken})
	// A benign concurrent refresh is still a 401-class invalid-token outcome, but
	// with the distinct code so the handler keeps the winner's session cookie.
	assertKind(t, err, KindInvalidToken, errcode.CodeConcurrentRefresh)
	if len(tokens.revokedFamilies) != 0 {
		t.Fatalf("revoked families = %#v, want no revoke for a within-grace replay", tokens.revokedFamilies)
	}
	// The family survived, so its device record must too.
	if len(devices.removed) != 0 {
		t.Fatalf("removed = %#v, want no device removal for a within-grace replay", devices.removed)
	}
}

func TestRefreshRevokedTokenRejectsWithoutRedundantRevoke(t *testing.T) {
	service, users, _, tokens, _, _ := newTestService(t)
	devices := &fakeDevices{}
	service = withDevices(service, devices)
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
	// Benign concurrent refresh within the grace window: distinct code so the
	// handler does not clear the (winner's) session cookie.
	assertKind(t, err, KindInvalidToken, errcode.CodeConcurrentRefresh)
	// A revoked refresh token belongs to an already-cut family: the revoking
	// transaction wrote its blacklist outbox rows, so re-revoking here would find
	// no live token and deliver nothing. The service rejects without repeating it.
	if len(tokens.revokedFamilies) != 0 {
		t.Fatalf("revoked families = %#v, want no redundant revoke of an already-revoked family", tokens.revokedFamilies)
	}
	// Within the grace window the revoked token is a benign concurrent refresh:
	// the family was not cut again and the device record survives it.
	if len(devices.removed) != 0 {
		t.Fatalf("removed = %#v, want no device removal for a within-grace refresh", devices.removed)
	}
	if len(blacklist.jtis) != 0 {
		t.Fatalf("blacklist = %+v, want no synchronous delivery for an already-revoked family", blacklist)
	}
}

func TestRefreshExpiredActiveTokenDoesNotRevokeFamily(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)
	devices := &fakeDevices{}
	service = withDevices(service, devices)
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
	// The session anchor is dead, so the device record must not keep showing a
	// live login — but this is not a revoke, only a cleanup.
	if len(devices.removed) != 1 || devices.removed[0] != tokens.createdRefresh.FamilyID {
		t.Fatalf("removed = %#v, want the expired session's device record", devices.removed)
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
	if len(tokens.auditEntries) == 0 {
		t.Fatalf("audit outboxes = %#v, want a successful refresh audit enqueued", tokens.auditEntries)
	}
	lastOutbox := tokens.auditEntries[len(tokens.auditEntries)-1]
	if lastOutbox.Action != "refresh" || lastOutbox.Success == nil || !*lastOutbox.Success {
		t.Fatalf("audit outboxes = %#v, want successful refresh audit", tokens.auditEntries)
	}

	tokens.rotateErr = repository.ErrTokenReplay
	_, err = service.Refresh(context.Background(), RefreshInput{RefreshToken: refresh.RefreshToken})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)
	// The replay audit stays synchronous (the failure path is not the hot path).
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
		assertKind(t, err, KindLoginFailed, errcode.CodePasswordInvalid)
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
	if result.FamilyID != familyID || tokens.revokedFamilies[len(tokens.revokedFamilies)-1] != familyID || !slices.Contains(blacklist.jtis, claims.ID) {
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
	if len(blacklist.jtis) != 0 {
		t.Fatalf("blacklist jtis = %v, want no delivery when DB revoke fails", blacklist.jtis)
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

func TestLogoutRejectsRevokedAccessMetadataAndRevokesExpired(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)
	now := service.now()

	// A revoked access token is a dead session: idempotent failure (the handler
	// maps it to success and clears the cookie).
	login, claims := loginForLogout(t, &service)
	tokens.createdAccess.RevokedAt = &now
	_, err := service.Logout(context.Background(), LogoutInput{PrincipalJTI: claims.ID, PrincipalUserID: 42, RefreshToken: login.RefreshToken})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)

	// An expired access token still names a live refresh family — logout must
	// revoke it (the stale-tab case the expired-tolerant gate admits), not treat
	// expiry as "nothing to revoke".
	login2, claims2 := loginForLogout(t, &service)
	tokens.createdAccess.ExpiresAt = now.Add(-time.Second)
	if _, err := service.Logout(context.Background(), LogoutInput{PrincipalJTI: claims2.ID, PrincipalUserID: 42, RefreshToken: login2.RefreshToken}); err != nil {
		t.Fatalf("logout with an expired access token should still revoke the family, got %v", err)
	}
	if len(tokens.revokedFamilies) != 1 {
		t.Fatalf("revoked families = %#v, want exactly one (the expired session's)", tokens.revokedFamilies)
	}
}

func TestLogoutIgnoresDeadRefreshToken(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)
	now := service.now()

	// A dead refresh token no longer blocks logout: the service revokes the
	// access token's own family (the session being logged out). Each case needs a
	// fresh login — the previous logout revoked that session's family.
	for _, mutate := range []func(*fakeTokens){
		func(t *fakeTokens) { t.createdRefresh.RevokedAt = &now },
		func(t *fakeTokens) { t.createdRefresh.ExpiresAt = now.Add(-time.Second) },
	} {
		login2, claims2 := loginForLogout(t, &service)
		mutate(tokens)
		if _, err := service.Logout(context.Background(), LogoutInput{PrincipalJTI: claims2.ID, PrincipalUserID: 42, RefreshToken: login2.RefreshToken}); err != nil {
			t.Fatalf("logout with a dead refresh token should still succeed, got %v", err)
		}
	}
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

// The anonymous request path must be identical for known and unknown accounts:
// both enqueue the same normalized job and neither performs SMTP or Redis work.
func TestForgotPasswordSendCodeHidesAccountExistence(t *testing.T) {
	for _, email := range []string{"nobody@njupt.edu.cn", "user@njupt.edu.cn"} {
		t.Run(email, func(t *testing.T) {
			service := newRegisterService(t)
			dispatcher := service.ForgotPasswords.(*fakeForgotPasswordDispatcher)
			result, err := service.ForgotPasswordSendCode(context.Background(), ForgotPasswordInput{Email: email, ClientIP: "127.0.0.1"})
			if err != nil {
				t.Fatalf("ForgotPasswordSendCode returned error: %v", err)
			}
			if result.Email != email || result.ExpiresIn != 300 {
				t.Fatalf("result = %+v, want uniform accepted shape", result)
			}
			if len(dispatcher.jobs) != 1 || dispatcher.jobs[0].Email != email {
				t.Fatalf("jobs = %+v, want one normalized job", dispatcher.jobs)
			}
			if sent := len(service.Mailer.(*fakeMailer).sent); sent != 0 {
				t.Fatalf("mailer sent=%d in request path, want 0", sent)
			}
		})
	}
}

func TestForgotPasswordSendCodeReturnsAcceptedWhenQueueIsFull(t *testing.T) {
	service := newRegisterService(t)
	service.ForgotPasswords = &fakeForgotPasswordDispatcher{accepted: false}
	result, err := service.ForgotPasswordSendCode(context.Background(), ForgotPasswordInput{Email: "user@njupt.edu.cn"})
	if err != nil || result.Email != "user@njupt.edu.cn" || result.ExpiresIn != 300 {
		t.Fatalf("result/error = %+v/%v, want uniform accepted response", result, err)
	}
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
	_, err := service.Register(context.Background(), RegisterInput{RegisterTicket: "reg_missing", Password: "newpassword", Name: "x", StudentID: "B24040525", PhoneNumber: "1", QQNumber: "1", College: string(model.CollegeOther), Major: "CS"})
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

// fakeOAuthRegistrationStore stands in for the Redis-backed parked-identity
// store, with GetDel semantics so a consumed state is gone.
type fakeOAuthRegistrationStore struct {
	states  map[string]OAuthRegistrationPayload
	readErr error
}

func (s *fakeOAuthRegistrationStore) ConsumeRegistrationState(
	_ context.Context,
	state string,
) (OAuthRegistrationPayload, bool, error) {
	if s.readErr != nil {
		return OAuthRegistrationPayload{}, false, s.readErr
	}
	payload, ok := s.states[state]
	if !ok {
		return OAuthRegistrationPayload{}, false, nil
	}
	delete(s.states, state)
	return payload, true, nil
}

// oauthRegisterInput is a complete registration payload for the OAuth branch.
func oauthRegisterInput(registrationState, oauthState string) RegisterInput {
	return RegisterInput{
		RegisterTicket:    "reg_xxx",
		Password:          "newpassword",
		Name:              "New",
		StudentID:         "B24040099",
		PhoneNumber:       "13800138000",
		QQNumber:          "10000",
		College:           string(model.CollegeOther),
		Major:             "CS",
		RegistrationState: registrationState,
		OAuthState:        oauthState,
	}
}

// newOAuthRegisterService wires a register service with a parked GitHub identity
// under "rs_abc", issued alongside OAuth state "os_abc".
func newOAuthRegisterService(t *testing.T) (Service, *fakeOAuthRegistrationStore) {
	t.Helper()
	service := newRegisterService(t)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_xxx", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("save register ticket: %v", err)
	}
	store := &fakeOAuthRegistrationStore{states: map[string]OAuthRegistrationPayload{
		"rs_abc": {
			Provider:     model.LoginMethodGitHub,
			ProviderID:   "145339646",
			IdentityData: model.JSONB(`{"login":"ptilopsis"}`),
			OAuthState:   "os_abc",
			AccessToken:  "gho_token",
		},
	}}
	service.OAuthRegistration = store
	return service, store
}

func TestRegisterWithOAuthStatePairCreatesIdentity(t *testing.T) {
	service, _ := newOAuthRegisterService(t)
	users := service.Users.(*fakeUsers)

	result, err := service.Register(context.Background(), oauthRegisterInput("rs_abc", "os_abc"))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if result.AccessToken == "" {
		t.Fatal("Register returned no access token")
	}
	// The binding must be persisted with the account, not afterwards.
	if users.registeredIdentity == nil {
		t.Fatal("no third-party identity was persisted with the registration")
	}
	if users.registeredIdentity.Provider != model.LoginMethodGitHub {
		t.Fatalf("identity provider = %q, want github", users.registeredIdentity.Provider)
	}
	if users.registeredIdentity.ProviderID != "145339646" {
		t.Fatalf("identity provider_id = %q, want 145339646", users.registeredIdentity.ProviderID)
	}
	if users.registeredIdentity.UserID == 0 {
		t.Fatal("identity was not linked to the created user")
	}
}

func TestRegisterRejectsMismatchedOAuthState(t *testing.T) {
	service, _ := newOAuthRegisterService(t)
	users := service.Users.(*fakeUsers)

	// PRD §4.5: a leaked registration_state is useless without the OAuth state
	// it was issued with. This is the check that makes that true.
	_, err := service.Register(context.Background(), oauthRegisterInput("rs_abc", "os_wrong"))
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
	if users.registeredIdentity != nil {
		t.Fatal("an identity was persisted despite a mismatched oauth_state")
	}
	if _, ok := users.byLogin["new@sast.fun"]; ok {
		t.Fatal("an account was created despite a mismatched oauth_state")
	}
}

func TestRegisterRejectsRegistrationStateWithoutOAuthState(t *testing.T) {
	service, store := newOAuthRegisterService(t)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)

	// Half a pair is rejected on shape, before anything is consumed.
	_, err := service.Register(context.Background(), oauthRegisterInput("rs_abc", ""))
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
	if _, ok := store.states["rs_abc"]; !ok {
		t.Fatal("registration_state was consumed by a malformed request")
	}
	if _, ok := tickets.tickets["reg_xxx"]; !ok {
		t.Fatal("register ticket was consumed by a malformed request")
	}
}

func TestRegisterRejectsOAuthStateWithoutRegistrationState(t *testing.T) {
	service, _ := newOAuthRegisterService(t)
	_, err := service.Register(context.Background(), oauthRegisterInput("", "os_abc"))
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

func TestRegisterRejectsUnknownRegistrationState(t *testing.T) {
	service, _ := newOAuthRegisterService(t)
	_, err := service.Register(context.Background(), oauthRegisterInput("rs_missing", "os_abc"))
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

func TestRegisterKeepsRegistrationStateWhenStudentIDClashes(t *testing.T) {
	service, store := newOAuthRegisterService(t)
	users := service.Users.(*fakeUsers)
	// Occupy the student ID so the registration is rejected before the OAuth
	// pair is resolved.
	existing := &model.User{
		ID: 7, StudentID: "B24040099", LoginEmail: "taken@sast.fun",
		Role: model.UserRoleFreshman, State: model.UserStateNJUPTer,
	}
	users.byID[existing.ID] = existing
	users.byLogin[existing.LoginEmail] = existing

	_, err := service.Register(context.Background(), oauthRegisterInput("rs_abc", "os_abc"))
	assertKind(t, err, KindConflict, errcode.CodeStudentIDOccupied)
	// The parked identity is resolved after the recoverable conflict checks, so
	// a fixable clash does not cost the user another trip through the provider.
	if _, ok := store.states["rs_abc"]; !ok {
		t.Fatal("registration_state was consumed by a recoverable student-ID conflict")
	}
}

func TestRegisterRejectsParkedStateWithEmptyOAuthState(t *testing.T) {
	service, store := newOAuthRegisterService(t)
	// A payload stored without an oauth_state would compare equal to an empty
	// submitted value and silently disable the double binding. The shape check in
	// Register blocks the empty submission, but this guard is what makes the
	// comparison safe on its own.
	store.states["rs_empty"] = OAuthRegistrationPayload{
		Provider:   model.LoginMethodGitHub,
		ProviderID: "145339646",
		OAuthState: "",
	}
	_, err := service.Register(context.Background(), oauthRegisterInput("rs_empty", "os_abc"))
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)

	users := service.Users.(*fakeUsers)
	if users.registeredIdentity != nil {
		t.Fatal("an identity was persisted from a payload with no oauth_state")
	}
}

func TestRegisterConsumesRegistrationStateEvenOnMismatch(t *testing.T) {
	service, store := newOAuthRegisterService(t)

	// The pair was presented and failed. Leaving it live would let an attacker
	// holding a leaked registration_state keep guessing OAuth states.
	if _, err := service.Register(context.Background(), oauthRegisterInput("rs_abc", "os_wrong")); err == nil {
		t.Fatal("Register succeeded with a mismatched oauth_state")
	}
	if _, ok := store.states["rs_abc"]; ok {
		t.Fatal("registration_state survived a failed double-binding check")
	}
}

func TestRegisterFailsClosedWhenRegistrationStoreIsDown(t *testing.T) {
	service, store := newOAuthRegisterService(t)
	store.readErr = errors.New("redis is down")
	users := service.Users.(*fakeUsers)

	// Falling through would create an unbound account for a user who asked to
	// register through GitHub, with no way for them to tell.
	_, err := service.Register(context.Background(), oauthRegisterInput("rs_abc", "os_abc"))
	assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	if _, ok := users.byLogin["new@sast.fun"]; ok {
		t.Fatal("an account was created while the registration store was down")
	}
}

func TestRegisterRejectsOAuthBranchWhenStoreNotConfigured(t *testing.T) {
	service := newRegisterService(t)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_xxx", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("save register ticket: %v", err)
	}
	// OAuthRegistration is nil: no third-party providers are configured.
	_, err := service.Register(context.Background(), oauthRegisterInput("rs_abc", "os_abc"))
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

func TestRegisterWithoutOAuthPairCreatesNoIdentity(t *testing.T) {
	service, _ := newOAuthRegisterService(t)
	users := service.Users.(*fakeUsers)

	input := oauthRegisterInput("", "")
	if _, err := service.Register(context.Background(), input); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if users.registeredIdentity != nil {
		t.Fatal("a plain email registration persisted a third-party identity")
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

// Subaddress aliases of one inbox must share the verification-code key, so
// foo+1@example.com and foo+2@example.com cannot mint unlimited distinct keys
// for the same mailbox (audit finding #8). The mail is still sent to the exact
// address the caller submitted.
func TestBindEmailSendCodeCollapsesSubaddressInCodeKey(t *testing.T) {
	service := newRegisterService(t)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)

	if _, err := service.BindEmailSendCode(context.Background(), BindEmailSendCodeInput{UserID: 42, Email: "extra+tag@gmail.com"}); err != nil {
		t.Fatalf("BindEmailSendCode(extra+tag) error = %v", err)
	}
	if _, ok := codes.codes[codeKey(string(mailer.VerificationPurposeBindEmail), "extra@gmail.com")]; !ok {
		t.Fatal("verification code not saved under the stripped mailbox key")
	}
	if _, ok := codes.codes[codeKey(string(mailer.VerificationPurposeBindEmail), "extra+tag@gmail.com")]; ok {
		t.Fatal("verification code unexpectedly saved under the tagged alias")
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

// A member whose login email is dead (its inbox no longer exists) can still
// reset through a bound other_mail identity: the identifier resolves to the
// account and the code reaches the address they actually read.
func TestResetPasswordResolvesBoundOtherMail(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	// The repository's FindAuthUserByLoginIdentifier resolves a bound other_mail
	// email through the identities join; the fake mirrors that by keying the
	// identifier map with the address.
	user := users.byID[42]
	users.byLogin["member@example.com"] = user
	resetPurpose := string(mailer.VerificationPurposeResetPassword)
	if err := codes.SaveVerificationCode(context.Background(), resetPurpose, "member@example.com", "123456", time.Minute); err != nil {
		t.Fatalf("save code: %v", err)
	}

	_, err := service.ResetPassword(context.Background(), ResetPasswordInput{
		Email: "member@example.com", Code: "123456", Password: "brand-new-password",
	})
	if err != nil {
		t.Fatalf("ResetPassword via bound email returned error: %v", err)
	}
	if service.Passwords.VerifyPassword(context.Background(), "brand-new-password", user.PasswordHash) != nil {
		t.Fatal("new password does not verify against the stored hash")
	}
}

// A deleted account must not be allowed to reset its password, even when the
// identifier resolves through a bound other_mail identity that is still in the
// identities table.
func TestResetPasswordRejectsDeletedAccount(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	user := users.byID[42]
	user.State = model.UserStateDeleted
	users.byLogin["member@example.com"] = user

	resetPurpose := string(mailer.VerificationPurposeResetPassword)
	if err := codes.SaveVerificationCode(context.Background(), resetPurpose, "member@example.com", "123456", time.Minute); err != nil {
		t.Fatalf("save code: %v", err)
	}

	_, err := service.ResetPassword(context.Background(), ResetPasswordInput{
		Email: "member@example.com", Code: "123456", Password: "brand-new-password",
	})
	assertKind(t, err, KindUserDeleted, errcode.CodeAccountDeleted)
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
	key, hash := sharedTestCredentials(t)
	passwords := auth.PasswordHasher{Random: repeatedReader(0x42)}
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
		Identities:       &fakeIdentities{users: users},
		Limiter:          &fakeLimiter{},
		Mailer:           &fakeMailer{},
		VerificationCode: &fakeVerificationCodeStore{},
		RegisterTicket:   &fakeRegisterTicketStore{},
		BindTicket:       &fakeBindTicketStore{},
		UnbindLimiter:    &fakeLimiter{},
		ForgotPasswords:  &fakeForgotPasswordDispatcher{accepted: true},
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
	key, hash := sharedTestCredentials(t)
	passwords := auth.PasswordHasher{Random: repeatedReader(0x42)}
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
		ForgotPasswords:  &fakeForgotPasswordDispatcher{accepted: true},
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
	_, hash := sharedTestCredentials(t)
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

	// A second valid account tries to redeem user 42's ticket; step-up passes
	// (the caller knows their own password), then the ownership check refuses it.
	_, hash := sharedTestCredentials(t)
	users := service.Users.(*fakeUsers)
	users.byID[99] = testUserWithHash(99, "other@njupt.edu.cn", model.UserStateOnSAST, hash)

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
		{name: "login email bound as identity", constraint: userLoginEmailIsIdentityConstraint, wantCode: errcode.CodeEmailAlreadyRegistered, wantKind: KindConflict},
		// The provider account was bound by someone else during the
		// registration_state window. The registrant's own fields are fine, so a
		// generic conflict would send them hunting through the wrong ones.
		{name: "third-party account taken mid-window", constraint: identityProviderConstraint, wantCode: errcode.CodeIdentityOccupied, wantKind: KindConflict},
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

func TestRegisterRollsBackAccountAndKeepsTicketWhenInitialSessionFails(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_atomic", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("SaveRegisterTicket() error = %v", err)
	}
	users.tokens.createErr = errors.New("token insert failed")

	_, err := service.Register(context.Background(), validRegisterInput("reg_atomic", "B24040999"))
	assertKind(t, err, KindInternal, errcode.CodeInternal)
	if _, ok := users.byLogin["new@sast.fun"]; ok {
		t.Fatal("account survived failed initial session transaction")
	}
	if _, ok := tickets.tickets["reg_atomic"]; !ok {
		t.Fatal("Register-Ticket was consumed after transaction rollback")
	}
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

func TestRegisterThrottlesPerRegisterTicket(t *testing.T) {
	service := newRegisterService(t)
	limiter := &fakeLimiter{result: LimitResult{Allowed: false, RetryAfter: time.Minute}}
	service.RegisterLimiter = limiter
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_xxx", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("save register ticket: %v", err)
	}

	_, err := service.Register(context.Background(), RegisterInput{
		RegisterTicket: "reg_xxx",
		Password:       "newpassword",
		Name:           "New User",
		StudentID:      "B24040099",
		PhoneNumber:    "13800138000",
		QQNumber:       "10000",
		College:        string(model.CollegeOther),
		Major:          "CS",
		ClientIP:       "198.51.100.7",
	})
	assertKind(t, err, KindRateLimited, errcode.CodeRateLimited)
	// Keyed by ticket, not IP: a campus NAT puts an entire building behind one
	// egress address, so an IP key would make enrollment traffic lock itself out.
	if got, want := limiter.calls[0], "register:ticket:reg_xxx"; got != want {
		t.Fatalf("limiter call = %q, want %q", got, want)
	}
	// A throttled call must leave the ticket spendable: the whole point of the
	// ticket surviving rejections is that the client can retry with it.
	if _, found, _ := tickets.PeekRegisterTicket(context.Background(), "reg_xxx"); !found {
		t.Fatal("Register-Ticket was consumed by a throttled call")
	}
}

// The cap bounds PBKDF2 cost, so it must not charge for rejections that never
// reach a derivation — otherwise a user mistyping their own form locks themselves
// out of the endpoint.
func TestRegisterDoesNotSpendQuotaOnCheapRejections(t *testing.T) {
	service := newRegisterService(t)
	limiter := &fakeLimiter{}
	service.RegisterLimiter = limiter
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_xxx", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("save register ticket: %v", err)
	}

	_, err := service.Register(context.Background(), RegisterInput{
		RegisterTicket: "reg_xxx",
		Password:       "short",
		Name:           "New User",
		StudentID:      "B24040099",
		PhoneNumber:    "13800138000",
		QQNumber:       "10000",
		College:        string(model.CollegeOther),
		Major:          "CS",
		ClientIP:       "198.51.100.7",
	})
	assertKind(t, err, KindValidationFailed, errcode.CodePasswordTooShort)
	if len(limiter.calls) != 0 {
		t.Fatalf("limiter calls = %v, want none for a rejection that never hashes", limiter.calls)
	}
}

func TestRegisterAllowsWhenLimiterUnavailable(t *testing.T) {
	service := newRegisterService(t)
	service.RegisterLimiter = &fakeLimiter{err: errors.New("redis unavailable")}
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_xxx", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("save register ticket: %v", err)
	}

	if _, err := service.Register(context.Background(), RegisterInput{
		RegisterTicket: "reg_xxx",
		Password:       "newpassword",
		Name:           "New User",
		StudentID:      "B24040099",
		PhoneNumber:    "13800138000",
		QQNumber:       "10000",
		College:        string(model.CollegeOther),
		Major:          "CS",
		ClientIP:       "198.51.100.7",
	}); err != nil {
		t.Fatalf("Register with a broken limiter = %v, want fail-open", err)
	}
}

// A replayed refresh token and an ordinary rotation share one action and, on
// failure, one error code. The outcome is what separates "a token leaked and we
// cut the family" from the mundane failures, so it has to be in the row.
func TestRefreshAuditRecordsReplayOutcome(t *testing.T) {
	service, _, _, tokens, audit, _ := newTestService(t)
	login, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	refresh, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: login.RefreshToken})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := auditOutcome(t, lastTokenAuditAction(t, tokens, "refresh")); got != refreshOutcomeRotated {
		t.Fatalf("successful refresh outcome = %q, want %q", got, refreshOutcomeRotated)
	}

	// Replay the token that was just rotated away.
	tokens.rotateErr = repository.ErrTokenReplay
	if _, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: refresh.RefreshToken}); err == nil {
		t.Fatal("Refresh accepted a replayed token")
	}
	entry := lastAuditAction(t, audit, "refresh")
	if got := auditOutcome(t, entry); got != refreshOutcomeReplayed {
		t.Fatalf("replayed refresh outcome = %q, want %q", got, refreshOutcomeReplayed)
	}
	// The family ID must travel with it, or the row cannot be tied to the tokens
	// that were revoked in response.
	if entry.ResourceID == nil || *entry.ResourceID == "" {
		t.Fatalf("audit entry = %+v, want the revoked family_id recorded", entry)
	}
}

// The already-revoked branch is a separate code path from the rotation-error
// branch above. Within the grace window it is a benign concurrent refresh, so it
// audits as concurrent_refresh — never as a replay, which would mislead a
// reviewer into treating routine multi-tab cold starts as replay attacks.
func TestRefreshAuditRecordsConcurrentOutcomeForRecentlyRevokedToken(t *testing.T) {
	service, _, _, _, audit, _ := newTestService(t)
	login, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: login.RefreshToken}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// The original token is now revoked within the grace window; presenting it
	// again is a benign concurrent refresh (the family is preserved).
	if _, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: login.RefreshToken}); err == nil {
		t.Fatal("Refresh accepted a revoked token")
	}
	if got := auditOutcome(t, lastAuditAction(t, audit, "refresh")); got != refreshOutcomeConcurrent {
		t.Fatalf("revoked-token outcome = %q, want %q", got, refreshOutcomeConcurrent)
	}
}

// An expired refresh token is benign, but it has to reach the log anyway: if only
// replays were recorded, a refresh_replayed row could not be told apart from the
// failures nobody wrote down.
func TestRefreshAuditRecordsExpiredOutcome(t *testing.T) {
	service, _, _, tokens, audit, _ := newTestService(t)
	login, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	// Age the stored token out against the service's fixed clock.
	for _, stored := range tokens.refreshByHash {
		stored.ExpiresAt = service.now().Add(-time.Minute)
	}

	if _, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: login.RefreshToken}); err == nil {
		t.Fatal("Refresh accepted an expired token")
	}
	if got := auditOutcome(t, lastAuditAction(t, audit, "refresh")); got != refreshOutcomeExpired {
		t.Fatalf("expired refresh outcome = %q, want %q", got, refreshOutcomeExpired)
	}
}

// A token presented against a different client is unreachable through the
// first-party flow, so it means a misrouted client or a token being probed.
func TestRefreshAuditRecordsClientMismatchOutcome(t *testing.T) {
	service, _, _, tokens, audit, _ := newTestService(t)
	login, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	for _, stored := range tokens.refreshByHash {
		stored.ClientID = 999
	}

	if _, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: login.RefreshToken}); err == nil {
		t.Fatal("Refresh accepted a token issued to another client")
	}
	if got := auditOutcome(t, lastAuditAction(t, audit, "refresh")); got != refreshOutcomeClientMismatch {
		t.Fatalf("client-mismatch outcome = %q, want %q", got, refreshOutcomeClientMismatch)
	}
}

// lastTokenAuditAction finds the most recent audit row the token repository
// recorded for action — the login/refresh success audits now write directly into
// the token transaction, so they are asserted on the token fake, not the audit
// fake.
func lastTokenAuditAction(t *testing.T, tokens *fakeTokens, action string) model.AuditLog {
	t.Helper()
	for i := len(tokens.auditEntries) - 1; i >= 0; i-- {
		if tokens.auditEntries[i].Action == action {
			return *tokens.auditEntries[i]
		}
	}
	t.Fatalf("no token audit entry with action %q in %#v", action, tokens.auditEntries)
	return model.AuditLog{}
}

func lastAuditAction(t *testing.T, audit *fakeAudit, action string) model.AuditLog {
	t.Helper()
	for i := len(audit.entries) - 1; i >= 0; i-- {
		if audit.entries[i].Action == action {
			return audit.entries[i]
		}
	}
	t.Fatalf("no audit entry with action %q in %#v", action, audit.entries)
	return model.AuditLog{}
}

func auditOutcome(t *testing.T, entry model.AuditLog) string {
	t.Helper()
	if len(entry.Detail) == 0 {
		t.Fatalf("audit entry %+v has no detail", entry)
	}
	var detail struct {
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(entry.Detail, &detail); err != nil {
		t.Fatalf("unmarshal audit detail %s: %v", entry.Detail, err)
	}
	return detail.Outcome
}

// The student ID cannot be read as an enrollment year, so the account has no
// derivable state. This rejection must sit with the other costless field checks:
// the Register-Ticket and the parked registration_state are both one-time, and a
// typo must not burn the OAuth authorization behind them.
func TestRegisterRejectsUnparseableStudentIDWithoutSpendingCredentials(t *testing.T) {
	service, store := newOAuthRegisterService(t)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)

	input := oauthRegisterInput("rs_abc", "os_abc")
	input.StudentID = "B1"
	_, err := service.Register(context.Background(), input)
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)

	if _, ok := tickets.tickets["reg_xxx"]; !ok {
		t.Fatal("Register-Ticket was consumed by an unreadable student ID")
	}
	if _, ok := store.states["rs_abc"]; !ok {
		t.Fatal("registration_state was consumed by an unreadable student ID: the applicant would have to re-authorize with GitHub")
	}
}
