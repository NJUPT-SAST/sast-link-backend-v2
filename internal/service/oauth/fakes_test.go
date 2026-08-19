package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }

type fakeUsers struct {
	byID map[int64]*model.User
	err  error
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

type fakeClients struct {
	byClientID map[string]*model.OAuthClient
	byID       map[int64]*model.OAuthClient
	err        error
}

func (f *fakeClients) FindActiveByClientID(_ context.Context, clientID string) (*model.OAuthClient, error) {
	if f.err != nil {
		return nil, f.err
	}
	client, ok := f.byClientID[clientID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return client, nil
}

type fakeAuthorizations struct {
	mutex              sync.Mutex
	byCode             map[string]*model.OAuthAuthorization
	created            []*model.OAuthAuthorization
	createErr          error
	consumeAs          error
	consumeUserVersion int64
}

func newFakeAuthorizations() *fakeAuthorizations {
	// consumeUserVersion defaults to activeUser().TokenVersion (2) so the
	// redemption's snapshot check passes for the stock user; tests that drive a
	// mismatch set consumeUserVersion explicitly.
	return &fakeAuthorizations{byCode: map[string]*model.OAuthAuthorization{}, consumeUserVersion: 2}
}

func (f *fakeAuthorizations) CreateWithGrant(_ context.Context, authorization *model.OAuthAuthorization) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	stored := *authorization
	f.byCode[authorization.Code] = &stored
	f.created = append(f.created, authorization)
	return nil
}

// Consume mirrors the repository's single-use contract, including returning the
// record alongside ErrAuthorizationReplayed so the caller can read its family.
func (f *fakeAuthorizations) Consume(_ context.Context, code string, now time.Time) (*model.OAuthAuthorization, int64, error) {
	if f.consumeAs != nil {
		return nil, 0, f.consumeAs
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	stored, ok := f.byCode[code]
	if !ok {
		return nil, 0, repository.ErrNotFound
	}
	if stored.IsUsed {
		return stored, f.consumeUserVersion, repository.ErrAuthorizationReplayed
	}
	if !stored.ExpiresAt.After(now) {
		return stored, f.consumeUserVersion, repository.ErrAuthorizationExpired
	}
	stored.IsUsed = true
	consumed := *stored
	return &consumed, f.consumeUserVersion, nil
}

func (f *fakeAuthorizations) ListGrantsByUser(_ context.Context, _ int64) ([]repository.OAuthGrant, error) {
	return nil, nil
}

func (f *fakeAuthorizations) DeleteByUserClient(_ context.Context, _, _ int64) error {
	return nil
}

func (f *fakeTokens) RevokeUserClientTokens(_ context.Context, userID, clientID int64, revokedAt time.Time) ([]model.BlacklistEntry, error) {
	if f.revokeErr != nil {
		return nil, f.revokeErr
	}
	var entries []model.BlacklistEntry
	for _, access := range f.accessByJTI {
		if access.UserID != userID || access.ClientID != clientID || access.RevokedAt != nil {
			continue
		}
		at := revokedAt
		access.RevokedAt = &at
		if access.ExpiresAt.After(revokedAt) {
			entries = append(entries, model.BlacklistEntry{TokenID: access.TokenID, ExpiresAt: access.ExpiresAt})
		}
	}
	for _, refresh := range f.refreshByHash {
		if refresh.UserID == userID && refresh.ClientID == clientID && refresh.RevokedAt == nil {
			at := revokedAt
			refresh.RevokedAt = &at
		}
	}
	return entries, nil
}

type fakeTokens struct {
	accessByJTI       map[string]*model.OAuthAccessToken
	refreshByHash     map[string]*model.OAuthRefreshToken
	createdAccess     *model.OAuthAccessToken
	createdRefresh    *model.OAuthRefreshToken
	rotatedAccess     *model.OAuthAccessToken
	rotatedRefresh    *model.OAuthRefreshToken
	revokedFamilies   []string
	auditEntries      []*model.AuditLog
	createErr         error
	rotateErr         error
	revokeErr         error
	originErr         error
	userVersionErr    error
	storedUserVersion int64
	// clientErr is returned by CreatePairWithUserAndClientLock when set,
	// simulating a refused client check (inactive, narrowed scope, deleted).
	clientErr error
	// now is the wall clock for family-lifetime decisions, mirroring the
	// repository's rotationTime := time.Now(). Tests that drive a fixed service
	// clock set it to that clock so origin+cap comparisons stay deterministic.
	now func() time.Time
}

func newFakeTokens() *fakeTokens {
	return &fakeTokens{
		accessByJTI:   map[string]*model.OAuthAccessToken{},
		refreshByHash: map[string]*model.OAuthRefreshToken{},
	}
}

func (f *fakeTokens) nowUTC() time.Time {
	if f.now != nil {
		return f.now().UTC()
	}
	return time.Now().UTC()
}

func (f *fakeTokens) CreatePair(_ context.Context, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) error {
	return f.CreatePairWithAudit(context.Background(), access, refresh, nil)
}

func (f *fakeTokens) CreatePairWithAudit(_ context.Context, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken, audit *model.AuditLog) error {
	if f.createErr != nil {
		return f.createErr
	}
	if audit != nil {
		f.auditEntries = append(f.auditEntries, audit)
	}
	f.createdAccess = access
	f.createdRefresh = refresh
	f.accessByJTI[access.TokenID] = access
	f.refreshByHash[refresh.TokenHash] = refresh
	return nil
}

// CreatePairWithUserAndClientLock mirrors the repository's user-and-client-lock
// write: it refuses when the stored version differs or the client check fails,
// and otherwise records like CreatePairWithAudit.
func (f *fakeTokens) CreatePairWithUserAndClientLock(_ context.Context, _ int64, _ int64, expected int64, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken, audit *model.AuditLog) error {
	if f.userVersionErr != nil {
		return f.userVersionErr
	}
	if f.storedUserVersion != 0 && f.storedUserVersion != expected {
		return repository.ErrUserStateChanged
	}
	if f.clientErr != nil {
		return f.clientErr
	}
	if f.createErr != nil {
		return f.createErr
	}
	if audit != nil {
		f.auditEntries = append(f.auditEntries, audit)
	}
	f.createdAccess = access
	f.createdRefresh = refresh
	f.accessByJTI[access.TokenID] = access
	f.refreshByHash[refresh.TokenHash] = refresh
	return nil
}

func (f *fakeTokens) RotateRefreshTokenWithAudit(
	ctx context.Context,
	familyID string,
	currentHash string,
	access *model.OAuthAccessToken,
	refresh *model.OAuthRefreshToken,
	audit *model.AuditLog,
) (time.Time, error) {
	if audit != nil {
		f.auditEntries = append(f.auditEntries, audit)
	}
	return f.RotateRefreshToken(ctx, familyID, currentHash, access, refresh)
}

func (f *fakeTokens) RotateRefreshTokenWithAuditCapped(
	ctx context.Context,
	familyID string,
	currentHash string,
	access *model.OAuthAccessToken,
	refresh *model.OAuthRefreshToken,
	audit *model.AuditLog,
	maxLifetime time.Duration,
) (time.Time, error) {
	origin, err := f.RotateRefreshTokenWithAudit(ctx, familyID, currentHash, access, refresh, audit)
	if err != nil {
		return origin, err
	}
	// Mirror the repository contract so service-level tests can exercise the cap
	// without a database: clamp the rotated expiry to origin+maxLifetime and
	// report a family-past-cap as ErrTokenFamilyExpired.
	if maxLifetime > 0 {
		now := f.nowUTC()
		if deadline := origin.Add(maxLifetime); !deadline.After(now) {
			return origin, repository.ErrTokenFamilyExpired
		} else if refresh.ExpiresAt.After(deadline) {
			refresh.ExpiresAt = deadline
		}
	}
	return origin, nil
}

func (f *fakeTokens) RotateRefreshToken(
	_ context.Context,
	familyID string,
	currentHash string,
	access *model.OAuthAccessToken,
	refresh *model.OAuthRefreshToken,
) (time.Time, error) {
	if f.rotateErr != nil {
		return time.Time{}, f.rotateErr
	}
	current, ok := f.refreshByHash[currentHash]
	if !ok {
		return time.Time{}, repository.ErrNotFound
	}
	if current.FamilyID != familyID {
		return time.Time{}, repository.ErrInvalidArgument
	}
	if f.originErr != nil {
		return time.Time{}, f.originErr
	}
	// Mirror the repository: the origin is the lowest-sequence row of the family.
	var origin *model.OAuthRefreshToken
	for _, candidate := range f.refreshByHash {
		if candidate.FamilyID != familyID {
			continue
		}
		if origin == nil || candidate.Sequence < origin.Sequence {
			origin = candidate
		}
	}
	if origin == nil {
		return time.Time{}, repository.ErrNotFound
	}
	revokedAt := time.Now().UTC()
	current.RevokedAt = &revokedAt
	f.rotatedAccess = access
	f.rotatedRefresh = refresh
	f.accessByJTI[access.TokenID] = access
	f.refreshByHash[refresh.TokenHash] = refresh
	return origin.CreatedAt, nil
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

func (f *fakeTokens) RevokeFamily(_ context.Context, familyID string, revokedAt time.Time) ([]model.BlacklistEntry, error) {
	if f.revokeErr != nil {
		return nil, f.revokeErr
	}
	f.revokedFamilies = append(f.revokedFamilies, familyID)
	var entries []model.BlacklistEntry
	for _, access := range f.accessByJTI {
		if access.FamilyID == nil || *access.FamilyID != familyID {
			continue
		}
		// Mirrors repository.RevokeFamily: already-revoked tokens are neither
		// re-revoked nor re-enqueued, so the entries equal the tokens this call cut.
		if access.RevokedAt != nil {
			continue
		}
		at := revokedAt
		access.RevokedAt = &at
		if access.ExpiresAt.After(revokedAt) {
			entries = append(entries, model.BlacklistEntry{TokenID: access.TokenID, ExpiresAt: access.ExpiresAt})
		}
	}
	for _, refresh := range f.refreshByHash {
		if refresh.FamilyID == familyID && refresh.RevokedAt == nil {
			at := revokedAt
			refresh.RevokedAt = &at
		}
	}
	return entries, nil
}

type fakeAudit struct {
	mutex   sync.Mutex
	entries []model.AuditLog
	err     error
}

func (f *fakeAudit) Create(_ context.Context, entry *model.AuditLog) error {
	if f.err != nil {
		return f.err
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.entries = append(f.entries, *entry)
	return nil
}

func (f *fakeAudit) actions() []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	actions := make([]string, 0, len(f.entries))
	for _, entry := range f.entries {
		actions = append(actions, entry.Action)
	}
	return actions
}

// outcomes collects the "outcome" detail value from every audit row, which is
// how the token endpoints distinguish a replay from a family-lifetime expiry.
func (f *fakeAudit) outcomes() []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	outcomes := make([]string, 0, len(f.entries))
	for _, entry := range f.entries {
		var detail map[string]any
		if err := json.Unmarshal(entry.Detail, &detail); err != nil {
			continue
		}
		if outcome, ok := detail["outcome"].(string); ok {
			outcomes = append(outcomes, outcome)
		}
	}
	return outcomes
}

type fakeProfiles struct {
	byUserID map[int64]*repository.PublicCard
	err      error
}

func (f *fakeProfiles) FindPublicCardByUserID(_ context.Context, userID int64) (*repository.PublicCard, error) {
	if f.err != nil {
		return nil, f.err
	}
	card, ok := f.byUserID[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return card, nil
}

type fakeRequests struct {
	mutex     sync.Mutex
	byID      map[string]AuthorizeRequestPayload
	peekTTL   time.Duration
	saveErr   error
	loadErr   error
	saveCalls int
}

func newFakeRequests() *fakeRequests {
	return &fakeRequests{
		byID:    map[string]AuthorizeRequestPayload{},
		peekTTL: 10 * time.Minute,
	}
}

func (f *fakeRequests) SaveAuthorizeRequest(
	_ context.Context,
	requestID string,
	payload AuthorizeRequestPayload,
	_ time.Duration,
) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.saveCalls++
	f.byID[requestID] = payload
	return nil
}

// PeekAuthorizeRequest reads without consuming; the stash survives the peek.
func (f *fakeRequests) PeekAuthorizeRequest(
	_ context.Context,
	requestID string,
) (AuthorizeRequestPayload, time.Duration, bool, error) {
	if f.loadErr != nil {
		return AuthorizeRequestPayload{}, 0, false, f.loadErr
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	payload, ok := f.byID[requestID]
	if !ok {
		return AuthorizeRequestPayload{}, 0, false, nil
	}
	return payload, f.peekTTL, true, nil
}

// ConsumeAuthorizeRequest mirrors GetDel: at most one caller sees a given stash.
func (f *fakeRequests) ConsumeAuthorizeRequest(
	_ context.Context,
	requestID string,
) (AuthorizeRequestPayload, bool, error) {
	if f.loadErr != nil {
		return AuthorizeRequestPayload{}, false, f.loadErr
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	payload, ok := f.byID[requestID]
	if !ok {
		return AuthorizeRequestPayload{}, false, nil
	}
	delete(f.byID, requestID)
	return payload, true, nil
}

type fakeBlacklist struct {
	mutex sync.Mutex
	jtis  []string
	err   error
}

func (f *fakeBlacklist) DeleteAuthStates(_ context.Context, jtis []string) error {
	if f.err != nil {
		return f.err
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.jtis = append(f.jtis, jtis...)
	return nil
}

type fakeLimiter struct {
	mutex  sync.Mutex
	result LimitResult
	err    error
	calls  []string
}

func (f *fakeLimiter) Allow(_ context.Context, endpoint, subject string) (LimitResult, error) {
	f.mutex.Lock()
	f.calls = append(f.calls, endpoint+":"+subject)
	f.mutex.Unlock()
	if f.err != nil {
		return LimitResult{}, f.err
	}
	if f.result == (LimitResult{}) {
		return LimitResult{Allowed: true}, nil
	}
	return f.result, nil
}

func (f *fakeLimiter) callsSnapshot() []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

// harness bundles a Service with the fakes behind it so tests can assert on both.
type harness struct {
	service        Service
	users          *fakeUsers
	clients        *fakeClients
	authorizations *fakeAuthorizations
	tokens         *fakeTokens
	audit          *fakeAudit
	profiles       *fakeProfiles
	requests       *fakeRequests
	blacklist      *fakeBlacklist
	limiter        *fakeLimiter
	clock          fixedClock
}

const (
	testPublicClientID       = "sast-link-web"
	testConfidentialClientID = "third-party-app"
	// testFirstPartyAppClientID is an organization-owned registration that is not
	// the built-in client, so capability-scope (admin/user) tests can use a
	// first-party client without touching the protected built-in one.
	testFirstPartyAppClientID = "first-party-app"
	testClientSecret          = "third-party-secret-value"
	testRedirectURI           = "https://app.example.test/callback"
	// testVerifier and testChallenge are a valid RFC 7636 S256 pair.
	testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func testChallenge(t *testing.T) string {
	t.Helper()
	challenge, err := auth.PKCEChallengeS256(testVerifier)
	if err != nil {
		t.Fatalf("compute PKCE challenge: %v", err)
	}
	return challenge
}

func activeUser() *model.User {
	return &model.User{
		ID:           1,
		Role:         model.UserRoleMember,
		State:        model.UserStateOnSAST,
		Name:         "张三",
		LoginEmail:   "b24040101@njupt.edu.cn",
		TokenVersion: 2,
		UpdatedAt:    time.Date(2026, 7, 1, 8, 30, 0, 0, time.UTC),
	}
}

func publicClient() *model.OAuthClient {
	active := true
	return &model.OAuthClient{
		ID:           10,
		ClientID:     testPublicClientID,
		ClientName:   "SAST Link Web",
		ClientType:   model.ClientTypeFirstParty,
		RedirectURIs: model.StringArray{testRedirectURI},
		GrantTypes:   model.StringArray{grantTypeAuthorizationCode, grantTypeRefreshToken},
		Scopes:       model.StringArray{"openid", "profile", "email"},
		IsActive:     &active,
	}
}

func confidentialClient() *model.OAuthClient {
	active := true
	hash := auth.HashClientSecret(testClientSecret)
	return &model.OAuthClient{
		ID:               20,
		ClientID:         testConfidentialClientID,
		ClientName:       "Third Party App",
		ClientSecretHash: &hash,
		ClientType:       model.ClientTypeThirdParty,
		RedirectURIs:     model.StringArray{testRedirectURI},
		GrantTypes:       model.StringArray{grantTypeAuthorizationCode, grantTypeRefreshToken},
		// Registered narrower than the supported set, so scope-limit tests have
		// something to exceed.
		Scopes:   model.StringArray{"openid", "profile"},
		IsActive: &active,
	}
}

func firstPartyAppClient() *model.OAuthClient {
	active := true
	return &model.OAuthClient{
		ID:           30,
		ClientID:     testFirstPartyAppClientID,
		ClientName:   "First Party App",
		ClientType:   model.ClientTypeFirstParty,
		RedirectURIs: model.StringArray{testRedirectURI},
		GrantTypes:   model.StringArray{grantTypeAuthorizationCode, grantTypeRefreshToken},
		Scopes:       model.StringArray{"openid", "profile", "email"},
		IsActive:     &active,
	}
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	clock := fixedClock{value: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	jwtManager := &auth.JWTManager{
		Issuer:   "https://link.sast.fun/v2",
		Audience: []string{"sast-link-v2"},
		Active:   auth.JWTKeyPair{KID: "active", Private: key},
		Clock:    clock,
	}
	refreshManager, err := auth.NewRefreshTokenManager("0123456789abcdef0123456789abcdef", nil)
	if err != nil {
		t.Fatalf("construct refresh manager: %v", err)
	}

	user := activeUser()
	public := publicClient()
	confidential := confidentialClient()
	firstPartyApp := firstPartyAppClient()
	h := &harness{
		users:          &fakeUsers{byID: map[int64]*model.User{user.ID: user}},
		clients:        &fakeClients{byClientID: map[string]*model.OAuthClient{}, byID: map[int64]*model.OAuthClient{}},
		authorizations: newFakeAuthorizations(),
		tokens:         newFakeTokens(),
		audit:          &fakeAudit{},
		profiles:       &fakeProfiles{byUserID: map[int64]*repository.PublicCard{}},
		requests:       newFakeRequests(),
		blacklist:      &fakeBlacklist{},
		limiter:        &fakeLimiter{},
		clock:          clock,
	}
	for _, client := range []*model.OAuthClient{public, confidential, firstPartyApp} {
		h.clients.byClientID[client.ClientID] = client
		h.clients.byID[client.ID] = client
	}
	// The fake's family-lifetime decisions follow the same clock as the service,
	// so origin+cap comparisons are deterministic rather than tied to real time.
	h.tokens.now = func() time.Time { return clock.value }
	h.service = Service{
		Users:            h.users,
		Clients:          h.clients,
		Authorizations:   h.authorizations,
		Tokens:           h.tokens,
		Audit:            h.audit,
		Profiles:         h.profiles,
		Requests:         h.requests,
		Blacklist:        h.blacklist,
		AuthorizeLimiter: h.limiter,
		// Same fake behind all three, so a test can throttle any endpoint; the recorded
		// endpoint name in fakeLimiter.calls distinguishes them.
		ConsentInfoLimiter: h.limiter,
		ConsentLimiter:     h.limiter,
		GrantsLimiter:      h.limiter,
		TokenLimiter:       h.limiter,
		JWT:                jwtManager,
		RefreshTokens:      refreshManager,
		Clock:              clock,
		AccessTTL:          time.Hour,
		RefreshTTL:         30 * 24 * time.Hour,
		CodeTTL:            5 * time.Minute,
		RequestTTL:         10 * time.Minute,
		Issuer:             "https://link.sast.fun/v2",
	}
	return h
}

func validAuthorizeInput(t *testing.T) AuthorizeInput {
	t.Helper()
	return AuthorizeInput{
		ResponseType:        responseTypeCode,
		ClientID:            testPublicClientID,
		RedirectURI:         testRedirectURI,
		Scope:               "openid profile email",
		State:               "client-state",
		CodeChallenge:       testChallenge(t),
		CodeChallengeMethod: pkceMethodS256,
		Nonce:               "n-0S6_WzA2Mj",
		ClientIP:            "203.0.113.10",
		UserAgent:           "test-agent",
	}
}

// requireOAuthError asserts that err is an *Error carrying wantCode.
func requireOAuthError(t *testing.T, err error, wantCode string) {
	t.Helper()
	_ = oauthError(t, err, wantCode)
}

// oauthError asserts the same and returns the error, for tests that also need to
// inspect Kind, Redirectable or RetryAfter.
func oauthError(t *testing.T, err error, wantCode string) *Error {
	t.Helper()
	var oauthErr *Error
	if !errors.As(err, &oauthErr) {
		t.Fatalf("error = %v, want *oauth.Error", err)
	}
	if oauthErr.Code != wantCode {
		t.Fatalf("error code = %q, want %q (description %q)", oauthErr.Code, wantCode, oauthErr.Description)
	}
	return oauthErr
}
