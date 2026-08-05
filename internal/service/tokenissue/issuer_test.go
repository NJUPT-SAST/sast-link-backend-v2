package tokenissue

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }

func newTestIssuer(t *testing.T, clock auth.Clock) Issuer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
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
	return Issuer{JWT: jwtManager, Refresh: refreshManager, Clock: clock}
}

func testUser() *model.User {
	return &model.User{
		ID:           7,
		Role:         model.UserRoleMember,
		State:        model.UserStateOnSAST,
		TokenVersion: 3,
	}
}

func testClient() *model.OAuthClient {
	return &model.OAuthClient{ID: 42, ClientID: "sast-link-web", ClientType: model.ClientTypeFirstParty}
}

func validRequest() Request {
	return Request{
		User:       testUser(),
		Client:     testClient(),
		Scopes:     []string{"openid", "profile", "email"},
		AccessTTL:  time.Hour,
		RefreshTTL: 30 * 24 * time.Hour,
	}
}

func TestIssueBuildsConsistentPairRows(t *testing.T) {
	clock := fixedClock{value: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	issuer := newTestIssuer(t, clock)

	pair, err := issuer.Issue(validRequest())
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	// TokenRepository.validateTokenPair rejects a pair whose family, client, user
	// or scopes disagree, so these invariants are what make the rows insertable.
	if pair.Access.FamilyID == nil || *pair.Access.FamilyID != pair.Refresh.FamilyID {
		t.Fatalf("family IDs = %v / %q, want equal", pair.Access.FamilyID, pair.Refresh.FamilyID)
	}
	if pair.FamilyID != pair.Refresh.FamilyID {
		t.Fatalf("returned family %q does not match the rows' %q", pair.FamilyID, pair.Refresh.FamilyID)
	}
	if pair.Access.ClientID != 42 || pair.Refresh.ClientID != 42 {
		t.Fatalf("client IDs = %d / %d, want 42", pair.Access.ClientID, pair.Refresh.ClientID)
	}
	if pair.Access.UserID != 7 || pair.Refresh.UserID != 7 {
		t.Fatalf("user IDs = %d / %d, want 7", pair.Access.UserID, pair.Refresh.UserID)
	}
	equal, err := scope.Equal([]string(pair.Access.Scopes), []string(pair.Refresh.Scopes))
	if err != nil || !equal {
		t.Fatalf("scopes = %v / %v, want equal and valid (err %v)", pair.Access.Scopes, pair.Refresh.Scopes, err)
	}
	if pair.ScopeClaim != "openid profile email" {
		t.Fatalf("scope claim = %q, want canonical order", pair.ScopeClaim)
	}
	if !pair.Access.ExpiresAt.Equal(clock.value.Add(time.Hour)) {
		t.Fatalf("access expiry = %v, want %v", pair.Access.ExpiresAt, clock.value.Add(time.Hour))
	}
	if !pair.Refresh.ExpiresAt.Equal(clock.value.Add(30 * 24 * time.Hour)) {
		t.Fatalf("refresh expiry = %v, want the refresh TTL from now", pair.Refresh.ExpiresAt)
	}

	claims, err := issuer.JWT.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken returned error: %v", err)
	}
	if claims.Subject != "7" || claims.Role != "member" || claims.State != "on_sast" || claims.TokenVersion != 3 {
		t.Fatalf("claims = %+v, want the user's identity fields", claims)
	}
	// The JTI in the token must match the row, or the auth middleware's DB lookup
	// and the blacklist would both miss.
	if claims.ID != pair.Access.TokenID {
		t.Fatalf("token jti = %q, row token_id = %q; want equal", claims.ID, pair.Access.TokenID)
	}
	if hash, hashErr := issuer.Refresh.HashRefreshToken(pair.RefreshToken); hashErr != nil || hash != pair.Refresh.TokenHash {
		t.Fatalf("refresh hash = %q (err %v), row hash = %q", hash, hashErr, pair.Refresh.TokenHash)
	}
}

func TestIssueContinuesExistingFamily(t *testing.T) {
	clock := fixedClock{value: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	issuer := newTestIssuer(t, clock)

	request := validRequest()
	request.FamilyID = "family-1"
	request.Sequence = 4

	pair, err := issuer.Issue(request)
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if pair.FamilyID != "family-1" || pair.Refresh.Sequence != 4 {
		t.Fatalf("family/sequence = %q/%d, want family-1/4", pair.FamilyID, pair.Refresh.Sequence)
	}
}

func TestIssueGeneratesDistinctFamiliesAndJTIs(t *testing.T) {
	clock := fixedClock{value: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	issuer := newTestIssuer(t, clock)

	first, err := issuer.Issue(validRequest())
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	second, err := issuer.Issue(validRequest())
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if first.FamilyID == second.FamilyID {
		t.Fatal("two fresh issuances share a family ID")
	}
	if first.Access.TokenID == second.Access.TokenID {
		t.Fatal("two fresh issuances share a JTI")
	}
	if first.RefreshToken == second.RefreshToken {
		t.Fatal("two fresh issuances share a refresh token")
	}
}

func TestIssueRejectsInvalidRequests(t *testing.T) {
	clock := fixedClock{value: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	issuer := newTestIssuer(t, clock)

	tests := []struct {
		name    string
		mutate  func(*Request)
		wantErr error
	}{
		{name: "nil user", mutate: func(r *Request) { r.User = nil }, wantErr: ErrInvalidInput},
		{name: "nil client", mutate: func(r *Request) { r.Client = nil }, wantErr: ErrInvalidInput},
		{name: "zero access TTL", mutate: func(r *Request) { r.AccessTTL = 0 }, wantErr: ErrInvalidInput},
		{name: "negative refresh TTL", mutate: func(r *Request) { r.RefreshTTL = -time.Hour }, wantErr: ErrInvalidInput},
		{name: "negative sequence", mutate: func(r *Request) { r.Sequence = -1 }, wantErr: ErrInvalidInput},
		{name: "scopes without openid", mutate: func(r *Request) { r.Scopes = []string{"profile"} }, wantErr: scope.ErrInvalid},
		{name: "empty scopes", mutate: func(r *Request) { r.Scopes = nil }, wantErr: scope.ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest()
			test.mutate(&request)
			if _, err := issuer.Issue(request); !errors.Is(err, test.wantErr) {
				t.Fatalf("Issue error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestIssueRequiresConfiguredManagers(t *testing.T) {
	if _, err := (Issuer{}).Issue(validRequest()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Issue error = %v, want ErrNotConfigured", err)
	}
}
