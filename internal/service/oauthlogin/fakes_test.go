package oauthlogin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/provider"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/tokenissue"
)

// errStoreDown stands in for a Redis outage, so tests can assert the
// fail-closed behavior the PRD requires.
var errStoreDown = errors.New("redis is down")

// pgUniqueViolation wraps a real *pgconn.PgError so the service's
// duplicateConstraint dispatch is exercised as written, rather than against a
// stand-in error type it would never see in production.
type pgUniqueViolation struct {
	constraint string
}

func (e *pgUniqueViolation) Error() string {
	return "duplicate key value violates unique constraint " + e.constraint
}

func (e *pgUniqueViolation) Unwrap() error {
	return &pgconn.PgError{
		Code:           pgerrcode.UniqueViolation,
		ConstraintName: e.constraint,
	}
}

type fakeProvider struct {
	authorizeURL string
	identity     *provider.Identity
	err          error
	calls        int
}

func (p *fakeProvider) AuthorizeURL(state string) string {
	return p.authorizeURL + "?state=" + state
}

func (p *fakeProvider) Exchange(_ context.Context, _ string, _ string) (*provider.Identity, error) {
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	return p.identity, nil
}

type fakeUserRepository struct {
	byID map[int64]*model.User
}

func (r *fakeUserRepository) FindByID(_ context.Context, userID int64) (*model.User, error) {
	user, ok := r.byID[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	clone := *user
	return &clone, nil
}

type fakeIdentityRepository struct {
	mu sync.Mutex
	// byProvider is keyed by provider + "\x00" + providerID.
	byProvider map[string]*model.Identity
	nextID     int64
	createErr  error
	updateErr  error
	updated    map[int64]repository.IdentityCredentialUpdate
}

func newFakeIdentityRepository() *fakeIdentityRepository {
	return &fakeIdentityRepository{
		byProvider: make(map[string]*model.Identity),
		nextID:     1,
		updated:    make(map[int64]repository.IdentityCredentialUpdate),
	}
}

func identityKey(name model.LoginMethod, providerID string) string {
	return string(name) + "\x00" + providerID
}

func (r *fakeIdentityRepository) put(identity *model.Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if identity.ID == 0 {
		identity.ID = r.nextID
		r.nextID++
	}
	r.byProvider[identityKey(identity.Provider, identity.ProviderID)] = identity
}

func (r *fakeIdentityRepository) FindByProviderID(
	_ context.Context,
	name model.LoginMethod,
	providerID string,
) (*model.Identity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	identity, ok := r.byProvider[identityKey(name, providerID)]
	if !ok {
		return nil, repository.ErrNotFound
	}
	clone := *identity
	return &clone, nil
}

func (r *fakeIdentityRepository) CreateWithinLimit(
	_ context.Context,
	identity *model.Identity,
	limit int64,
) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.mu.Lock()
	var owned int64
	for _, existing := range r.byProvider {
		if existing.UserID == identity.UserID && existing.Provider == identity.Provider {
			owned++
		}
	}
	r.mu.Unlock()
	if owned >= limit {
		return repository.ErrLimitExceeded
	}
	r.put(identity)
	return nil
}

func (r *fakeIdentityRepository) UpdateProviderCredentials(
	_ context.Context,
	identityID int64,
	update repository.IdentityCredentialUpdate,
) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updated[identityID] = update
	return nil
}

type fakeStateStore struct {
	states  map[string]StatePayload
	saveErr error
	readErr error
}

func newFakeStateStore() *fakeStateStore {
	return &fakeStateStore{states: make(map[string]StatePayload)}
}

func (s *fakeStateStore) SaveOAuthState(
	_ context.Context,
	state string,
	payload StatePayload,
	_ time.Duration,
) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.states[state] = payload
	return nil
}

func (s *fakeStateStore) ConsumeOAuthState(
	_ context.Context,
	state string,
) (StatePayload, bool, error) {
	if s.readErr != nil {
		return StatePayload{}, false, s.readErr
	}
	payload, ok := s.states[state]
	if !ok {
		return StatePayload{}, false, nil
	}
	// GetDel semantics: a consumed state is gone, so a replay finds nothing.
	delete(s.states, state)
	return payload, true, nil
}

type fakeRegistrationStore struct {
	states  map[string]RegistrationPayload
	saveErr error
	readErr error
}

func newFakeRegistrationStore() *fakeRegistrationStore {
	return &fakeRegistrationStore{states: make(map[string]RegistrationPayload)}
}

func (s *fakeRegistrationStore) SaveRegistrationState(
	_ context.Context,
	state string,
	payload RegistrationPayload,
	_ time.Duration,
) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.states[state] = payload
	return nil
}

func (s *fakeRegistrationStore) ConsumeRegistrationState(
	_ context.Context,
	state string,
) (RegistrationPayload, bool, error) {
	if s.readErr != nil {
		return RegistrationPayload{}, false, s.readErr
	}
	payload, ok := s.states[state]
	if !ok {
		return RegistrationPayload{}, false, nil
	}
	delete(s.states, state)
	return payload, true, nil
}

type fakeLoginCodeStore struct {
	codes   map[string]int64
	saveErr error
	readErr error
}

func newFakeLoginCodeStore() *fakeLoginCodeStore {
	return &fakeLoginCodeStore{codes: make(map[string]int64)}
}

func (s *fakeLoginCodeStore) SaveLoginCode(
	_ context.Context,
	code string,
	userID int64,
	_ time.Duration,
) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.codes[code] = userID
	return nil
}

func (s *fakeLoginCodeStore) ConsumeLoginCode(_ context.Context, code string) (int64, bool, error) {
	if s.readErr != nil {
		return 0, false, s.readErr
	}
	userID, ok := s.codes[code]
	if !ok {
		return 0, false, nil
	}
	delete(s.codes, code)
	return userID, true, nil
}

type fakeClientRepository struct {
	client *model.OAuthClient
	err    error
}

func (r *fakeClientRepository) FindActiveByClientID(
	_ context.Context,
	_ string,
) (*model.OAuthClient, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.client, nil
}

type fakeTokenRepository struct {
	pairs int
	err   error

	revoked   []string
	revokeErr error
}

func (r *fakeTokenRepository) CreatePair(
	_ context.Context,
	_ *model.OAuthAccessToken,
	_ *model.OAuthRefreshToken,
) error {
	if r.err != nil {
		return r.err
	}
	r.pairs++
	return nil
}

func (r *fakeTokenRepository) RevokeFamily(_ context.Context, familyID string, _ time.Time) ([]model.BlacklistEntry, error) {
	if r.revokeErr != nil {
		return nil, r.revokeErr
	}
	r.revoked = append(r.revoked, familyID)
	return nil, nil
}

type fakeAuditRepository struct {
	mu      sync.Mutex
	entries []model.AuditLog
	err     error
}

func (r *fakeAuditRepository) Create(_ context.Context, entry *model.AuditLog) error {
	if r.err != nil {
		return r.err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, *entry)
	return nil
}

func (r *fakeAuditRepository) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	actions := make([]string, 0, len(r.entries))
	for _, entry := range r.entries {
		actions = append(actions, entry.Action)
	}
	return actions
}

// fixedClock is a deterministic auth.Clock.
type fixedClock struct {
	instant time.Time
}

func (c fixedClock) Now() time.Time { return c.instant }

// newTestService assembles a Service with in-memory doubles and a real token
// issuer, so issued tokens are genuinely signed rather than stubbed.
func newTestService(t *testing.T) (Service, *testDoubles) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	clock := fixedClock{instant: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)}
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

	doubles := &testDoubles{
		GitHub: &fakeProvider{
			authorizeURL: "https://github.test/authorize",
			identity: &provider.Identity{
				ProviderID:  "145339646",
				DisplayName: "Ptilopsis",
				AvatarURL:   "https://avatars.test/p.png",
				Data:        map[string]any{"login": "ptilopsis"},
				AccessToken: "gho_token",
			},
		},
		Users:        &fakeUserRepository{byID: make(map[int64]*model.User)},
		Identities:   newFakeIdentityRepository(),
		States:       newFakeStateStore(),
		Registration: newFakeRegistrationStore(),
		LoginCodes:   newFakeLoginCodeStore(),
		Clients: &fakeClientRepository{client: &model.OAuthClient{
			ID: 1, ClientID: "sast-link-web", IsActive: boolPtr(true),
		}},
		Tokens: &fakeTokenRepository{},
		Audits: &fakeAuditRepository{},
	}

	service := Service{
		Providers: map[model.LoginMethod]ProviderClient{
			model.LoginMethodGitHub: doubles.GitHub,
		},
		Users:             doubles.Users,
		Identities:        doubles.Identities,
		Clients:           doubles.Clients,
		Tokens:            doubles.Tokens,
		Audits:            doubles.Audits,
		States:            doubles.States,
		RegistrationState: doubles.Registration,
		LoginCodes:        doubles.LoginCodes,
		Issuer: tokenissue.Issuer{
			JWT:     jwtManager,
			Refresh: refreshManager,
			Clock:   clock,
		},
		Clock:            clock,
		InternalClientID: "sast-link-web",
		AllowedRedirects: []string{"https://link.sast.fun/callback"},
		DefaultRedirect:  "https://link.sast.fun/callback",
		AccessTTL:        time.Hour,
		RefreshTTL:       30 * 24 * time.Hour,
	}
	return service, doubles
}

type testDoubles struct {
	GitHub       *fakeProvider
	Users        *fakeUserRepository
	Identities   *fakeIdentityRepository
	States       *fakeStateStore
	Registration *fakeRegistrationStore
	LoginCodes   *fakeLoginCodeStore
	Clients      *fakeClientRepository
	Tokens       *fakeTokenRepository
	Audits       *fakeAuditRepository
	Devices      *fakeDeviceStore
	Blacklist    *fakeBlacklist
}

// fakeDeviceStore records registrations and removals and reports an optional
// eviction, the way the Redis store reports the member the per-user cap
// displaced.
type fakeDeviceStore struct {
	registrations []deviceRegistration
	removed       []string
	registerErr   error
	evicted       string
}

type deviceRegistration struct {
	userID   int64
	deviceID string
	ua       string
	ip       string
}

func (f *fakeDeviceStore) RegisterDevice(_ context.Context, userID int64, deviceID, ua, ip string, _ time.Time) (string, error) {
	if f.registerErr != nil {
		return f.evicted, f.registerErr
	}
	f.registrations = append(f.registrations, deviceRegistration{userID: userID, deviceID: deviceID, ua: ua, ip: ip})
	return f.evicted, nil
}

func (f *fakeDeviceStore) RemoveDevice(_ context.Context, _ int64, deviceID string) error {
	f.removed = append(f.removed, deviceID)
	return nil
}

// fakeBlacklist records batch deliveries.
type fakeBlacklist struct {
	batches []map[string]time.Duration
	err     error
}

func (f *fakeBlacklist) BlacklistJTIBatch(_ context.Context, entries map[string]time.Duration) error {
	if f.err != nil {
		return f.err
	}
	f.batches = append(f.batches, entries)
	return nil
}

func TestFakeDeviceStoreRegistration(t *testing.T) {
	store := &fakeDeviceStore{evicted: "family-x"}
	evicted, err := store.RegisterDevice(context.Background(), 1, "family-1", "ua", "ip", time.Now())
	if err != nil || evicted != "family-x" {
		t.Fatalf("evicted = %q, err = %v", evicted, err)
	}
}

// fakeLimiter records the (endpoint, subject) pairs it was asked about so
// tests can assert the key shape, not just the decision.
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

func boolPtr(value bool) *bool { return &value }
