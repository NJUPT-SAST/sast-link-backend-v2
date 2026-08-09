package adminclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

type fakeClients struct {
	listed  []model.OAuthClient
	listErr error

	created    *model.OAuthClient
	createErr  error
	nextID     int64
	findResult *model.OAuthClient
	findErr    error

	updateFields  map[string]any
	updateRevoked bool
	updateEntries []model.BlacklistEntry
	updateErr     error
	updateCalls   int
}

func (f *fakeClients) List(_ context.Context) ([]model.OAuthClient, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listed, nil
}

func (f *fakeClients) Create(_ context.Context, client *model.OAuthClient) error {
	if f.createErr != nil {
		return f.createErr
	}
	if f.nextID == 0 {
		f.nextID = 7
	}
	client.ID = f.nextID
	f.created = client
	return nil
}

func (f *fakeClients) FindByID(_ context.Context, _ int64) (*model.OAuthClient, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	if f.findResult == nil {
		return nil, repository.ErrNotFound
	}
	return f.findResult, nil
}

func (f *fakeClients) UpdateAndRevoke(
	_ context.Context,
	_ int64,
	fields map[string]any,
	revokeTokens bool,
	_ time.Time,
) ([]model.BlacklistEntry, error) {
	f.updateCalls++
	f.updateFields = fields
	f.updateRevoked = revokeTokens
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	if !revokeTokens {
		return nil, nil
	}
	return f.updateEntries, nil
}

type fakeBlacklist struct {
	jtis []string
	err  error
}

func (f *fakeBlacklist) DeleteAuthStates(_ context.Context, jtis []string) error {
	f.jtis = jtis
	return f.err
}

type fakeAudit struct {
	entries []*model.AuditLog
	err     error
}

func (f *fakeAudit) Create(_ context.Context, entry *model.AuditLog) error {
	f.entries = append(f.entries, entry)
	return f.err
}

type testClock struct {
	value time.Time
}

func (c testClock) Now() time.Time { return c.value }

var testNow = time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

type harness struct {
	service   Service
	clients   *fakeClients
	blacklist *fakeBlacklist
	audit     *fakeAudit
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	clients := &fakeClients{}
	blacklist := &fakeBlacklist{}
	auditLog := &fakeAudit{}
	return &harness{
		service: Service{
			Clients:            clients,
			Blacklist:          blacklist,
			Audit:              auditLog,
			Secrets:            auth.ClientSecretHasher{},
			NewClientID:        func() (string, error) { return "generated-client-id", nil },
			Clock:              testClock{value: testNow},
			ProtectedClientIDs: []string{testProtectedClientID},
		},
		clients:   clients,
		blacklist: blacklist,
		audit:     auditLog,
	}
}

func validCreateInput() CreateClientInput {
	return CreateClientInput{
		ClientName:   "Test App",
		ClientType:   "third_party",
		RedirectURIs: []string{"https://app.test/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile"},
		AdminUserID:  99,
		ClientIP:     "203.0.113.7",
		UserAgent:    "console",
	}
}

// testProtectedClientID stands in for INTERNAL_OAUTH_CLIENT_ID: the built-in
// client the internal session flow resolves through an is_active filter.
const testProtectedClientID = "sast-link-web"

// protectedClient is the built-in registration, which must survive the admin API.
func protectedClient(id int64) *model.OAuthClient {
	client := activeClient(id)
	client.ClientID = testProtectedClientID
	client.ClientType = model.ClientTypeFirstParty
	return client
}

func activeClient(id int64) *model.OAuthClient {
	active := true
	return &model.OAuthClient{
		ID:           id,
		ClientID:     "existing-client",
		ClientName:   "Existing",
		ClientType:   model.ClientTypeThirdParty,
		RedirectURIs: model.StringArray{"https://existing.test/cb"},
		GrantTypes:   model.StringArray{"authorization_code"},
		Scopes:       model.StringArray{"openid"},
		IsActive:     &active,
	}
}

// assertKind fails unless err is a typed error of the wanted kind.
func assertKind(t *testing.T, err error, want Kind) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want a typed *Error", err)
	}
	if typed.Kind != want {
		t.Fatalf("error kind = %q, want %q (message %q)", typed.Kind, want, typed.Message)
	}
}
