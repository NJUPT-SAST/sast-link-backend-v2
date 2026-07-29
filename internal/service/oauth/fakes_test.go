package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	mutex     sync.Mutex
	byCode    map[string]*model.OAuthAuthorization
	created   []*model.OAuthAuthorization
	createErr error
	consumeAs error
}

func newFakeAuthorizations() *fakeAuthorizations {
	return &fakeAuthorizations{byCode: map[string]*model.OAuthAuthorization{}}
}

func (f *fakeAuthorizations) Create(_ context.Context, authorization *model.OAuthAuthorization) error {
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
func (f *fakeAuthorizations) Consume(_ context.Context, code string, now time.Time) (*model.OAuthAuthorization, error) {
	if f.consumeAs != nil {
		return nil, f.consumeAs
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	stored, ok := f.byCode[code]
	if !ok {
		return nil, repository.ErrNotFound
	}
	if stored.IsUsed {
		return stored, repository.ErrAuthorizationReplayed
	}
	if !stored.ExpiresAt.After(now) {
		return stored, repository.ErrAuthorizationExpired
	}
	stored.IsUsed = true
	consumed := *stored
	return &consumed, nil
}

type fakeTokens struct {
	accessByJTI     map[string]*model.OAuthAccessToken
	refreshByHash   map[string]*model.OAuthRefreshToken
	createdAccess   *model.OAuthAccessToken
	createdRefresh  *model.OAuthRefreshToken
	rotatedAccess   *model.OAuthAccessToken
	rotatedRefresh  *model.OAuthRefreshToken
	revokedFamilies []string
	createErr       error
	rotateErr       error
	revokeErr       error
	originErr       error
}

func newFakeTokens() *fakeTokens {
	return &fakeTokens{
		accessByJTI:   map[string]*model.OAuthAccessToken{},
		refreshByHash: map[string]*model.OAuthRefreshToken{},
	}
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

func (f *fakeTokens) RotateRefreshToken(
	_ context.Context,
	currentHash string,
	access *model.OAuthAccessToken,
	refresh *model.OAuthRefreshToken,
) error {
	if f.rotateErr != nil {
		return f.rotateErr
	}
	current, ok := f.refreshByHash[currentHash]
	if !ok {
		return repository.ErrNotFound
	}
	revokedAt := time.Now().UTC()
	current.RevokedAt = &revokedAt
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

// FindFamilyOriginCreatedAt mirrors the repository: the lowest-sequence row of the
// family, so tests observe the same auth_time semantics as production.
func (f *fakeTokens) FindFamilyOriginCreatedAt(_ context.Context, familyID string) (time.Time, error) {
	if f.originErr != nil {
		return time.Time{}, f.originErr
	}
	var origin *model.OAuthRefreshToken
	for _, refresh := range f.refreshByHash {
		if refresh.FamilyID != familyID {
			continue
		}
		if origin == nil || refresh.Sequence < origin.Sequence {
			origin = refresh
		}
	}
	if origin == nil {
		return time.Time{}, repository.ErrNotFound
	}
	return origin.CreatedAt, nil
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
		if access.RevokedAt == nil {
			at := revokedAt
			access.RevokedAt = &at
		}
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
	saveErr   error
	loadErr   error
	saveCalls int
}

func newFakeRequests() *fakeRequests {
	return &fakeRequests{byID: map[string]AuthorizeRequestPayload{}}
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
	mutex   sync.Mutex
	entries map[string]time.Duration
	err     error
}

func (f *fakeBlacklist) BlacklistJTIBatch(_ context.Context, entries map[string]time.Duration) error {
	if f.err != nil {
		return f.err
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.entries == nil {
		f.entries = map[string]time.Duration{}
	}
	for jti, ttl := range entries {
		f.entries[jti] = ttl
	}
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
	testClientSecret         = "third-party-secret-value"
	testRedirectURI          = "https://app.example.test/callback"
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

func newHarness(t *testing.T) *harness {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
	for _, client := range []*model.OAuthClient{public, confidential} {
		h.clients.byClientID[client.ClientID] = client
		h.clients.byID[client.ID] = client
	}
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
		// Same fake behind both, so a test can throttle either endpoint; the recorded
		// endpoint name in fakeLimiter.calls distinguishes them.
		TokenLimiter:  h.limiter,
		JWT:           jwtManager,
		RefreshTokens: refreshManager,
		Clock:         clock,
		AccessTTL:     time.Hour,
		RefreshTTL:    30 * 24 * time.Hour,
		CodeTTL:       5 * time.Minute,
		RequestTTL:    10 * time.Minute,
		CardBaseURL:   "https://link.sast.fun/card",
		Issuer:        "https://link.sast.fun/v2",
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
