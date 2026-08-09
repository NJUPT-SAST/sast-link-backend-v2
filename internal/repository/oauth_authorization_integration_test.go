package repository_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func testAuthorization(code string, clientID, userID int64, expiresAt time.Time) *model.OAuthAuthorization {
	redirectURI := "https://example.test/callback"
	familyID := "family-" + code
	nonce := "nonce-" + code
	return &model.OAuthAuthorization{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         &redirectURI,
		Scopes:              model.StringArray{"openid", "profile"},
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Nonce:               &nonce,
		FamilyID:            &familyID,
		ExpiresAt:           expiresAt,
	}
}

func TestOAuthAuthorizationRepositoryCreateAndConsume(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "authz-consume@njupt.edu.cn")
	client := createOAuthClient(t, database)
	authorizations := repository.NewOAuthAuthorization(database)

	authorization := testAuthorization("code-consume", client.ID, user.ID, time.Now().Add(5*time.Minute))
	if err := authorizations.Create(context.Background(), authorization); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if authorization.ID == 0 {
		t.Fatal("Create() left the authorization without a primary key")
	}

	consumed, err := authorizations.Consume(context.Background(), "code-consume", time.Now())
	if err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	if !consumed.IsUsed {
		t.Fatal("Consume() returned an authorization that is not marked used")
	}
	if consumed.CodeChallenge != authorization.CodeChallenge || consumed.Nonce == nil || *consumed.Nonce != "nonce-code-consume" {
		t.Fatalf("consumed authorization = %+v, want the stored PKCE and nonce values", consumed)
	}
	// created_at backs the ID Token's auth_time claim, so it must come back set.
	if consumed.CreatedAt.IsZero() {
		t.Fatal("consumed authorization has a zero created_at; auth_time would be unset")
	}
	assertAuthorizationUsed(t, database, "code-consume", true)
}

// A second redemption of the same code is the replay signal PRD §4.10 requires
// cascading on, so the error must carry the family ID the caller has to revoke.
func TestOAuthAuthorizationRepositoryConsumeReportsReplayWithFamily(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "authz-replay@njupt.edu.cn")
	client := createOAuthClient(t, database)
	authorizations := repository.NewOAuthAuthorization(database)

	if err := authorizations.Create(
		context.Background(),
		testAuthorization("code-replay", client.ID, user.ID, time.Now().Add(5*time.Minute)),
	); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := authorizations.Consume(context.Background(), "code-replay", time.Now()); err != nil {
		t.Fatalf("first Consume() error = %v", err)
	}

	replayed, err := authorizations.Consume(context.Background(), "code-replay", time.Now())
	if !errors.Is(err, repository.ErrAuthorizationReplayed) {
		t.Fatalf("second Consume() error = %v, want ErrAuthorizationReplayed", err)
	}
	if replayed == nil || replayed.FamilyID == nil || *replayed.FamilyID != "family-code-replay" {
		t.Fatalf("replayed authorization = %+v, want the family ID for cascade revocation", replayed)
	}
}

// Concurrent redemptions must produce exactly one winner. A read-then-update
// would let every caller pass the is_used check and mint a token pair each.
func TestOAuthAuthorizationRepositoryConsumeConcurrentSingleSuccess(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "authz-concurrent@njupt.edu.cn")
	client := createOAuthClient(t, database)
	authorizations := repository.NewOAuthAuthorization(database)

	if err := authorizations.Create(
		context.Background(),
		testAuthorization("code-concurrent", client.ID, user.ID, time.Now().Add(5*time.Minute)),
	); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	const contenders = 8
	start := make(chan struct{})
	results := make(chan error, contenders)
	var waitGroup sync.WaitGroup
	waitGroup.Add(contenders)
	for range contenders {
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := authorizations.Consume(context.Background(), "code-concurrent", time.Now())
			results <- err
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)

	successes := 0
	replays := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, repository.ErrAuthorizationReplayed):
			replays++
		default:
			t.Fatalf("concurrent Consume() error = %v, want nil or ErrAuthorizationReplayed", err)
		}
	}
	if successes != 1 || replays != contenders-1 {
		t.Fatalf("concurrent Consume() results = %d success, %d replay; want 1/%d", successes, replays, contenders-1)
	}
}

// An expired code was never redeemed, so it must not be marked used and must not
// be reported as a replay: there is no family to punish for the client's delay.
func TestOAuthAuthorizationRepositoryConsumeReportsExpiryWithoutMarkingUsed(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "authz-expired@njupt.edu.cn")
	client := createOAuthClient(t, database)
	authorizations := repository.NewOAuthAuthorization(database)

	issuedAt := time.Now().Add(-10 * time.Minute)
	authorization := testAuthorization("code-expired", client.ID, user.ID, issuedAt.Add(5*time.Minute))
	authorization.CreatedAt = issuedAt
	if err := authorizations.Create(context.Background(), authorization); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if _, err := authorizations.Consume(context.Background(), "code-expired", time.Now()); !errors.Is(err, repository.ErrAuthorizationExpired) {
		t.Fatalf("Consume() error = %v, want ErrAuthorizationExpired", err)
	}
	assertAuthorizationUsed(t, database, "code-expired", false)
}

// ListGrantsByUser is only exercised through fakes elsewhere, so this is the one
// test that proves the wire types scan against a real database. OAuthGrant's
// redirect_uris and scopes are text[] columns: a []string field has no
// sql.Scanner and would fail this Scan on the first grant. The test also pins the
// DISTINCT ON semantics — per client only the most recent consent comes back —
// and the user_id filter, without which another user's consent could leak into
// the list.
func TestOAuthAuthorizationRepositoryListGrantsScansTextArraysAndPicksLatest(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "grants-scan@njupt.edu.cn")
	otherUser := createUserWithProfile(t, repository.NewUser(database), "grants-scan-2@njupt.edu.cn")
	authorizations := repository.NewOAuthAuthorization(database)

	firstClient := &model.OAuthClient{
		ClientID:     "grants-client-a",
		ClientName:   "Grants Client A",
		ClientType:   model.ClientTypeFirstParty,
		RedirectURIs: model.StringArray{"https://a.test/cb"},
		GrantTypes:   model.StringArray{"authorization_code", "refresh_token"},
		Scopes:       model.StringArray{"openid", "profile"},
	}
	secondClient := &model.OAuthClient{
		ClientID:     "grants-client-b",
		ClientName:   "Grants Client B",
		ClientType:   model.ClientTypeThirdParty,
		RedirectURIs: model.StringArray{"https://b.test/cb", "https://b.test/cb2"},
		GrantTypes:   model.StringArray{"authorization_code"},
		Scopes:       model.StringArray{"openid", "email"},
	}
	// A disabled client's grants must still be listed — the user needs to see "an
	// app I authorized that is now off" — with is_active scanned as an explicit
	// false rather than nil.
	disabledClient := &model.OAuthClient{
		ClientID:     "grants-client-c",
		ClientName:   "Grants Client C",
		ClientType:   model.ClientTypeFirstParty,
		RedirectURIs: model.StringArray{"https://c.test/cb"},
		GrantTypes:   model.StringArray{"authorization_code"},
		Scopes:       model.StringArray{"openid"},
		IsActive:     boolPtr(false),
	}
	for _, client := range []*model.OAuthClient{firstClient, secondClient, disabledClient} {
		if err := database.Create(client).Error; err != nil {
			t.Fatalf("create OAuth client %s: %v", client.ClientID, err)
		}
	}

	// Two consents for client A, older then newer, with different scope sets.
	// created_at carries microsecond precision in PostgreSQL, so truncate the
	// source values or the round-tripped read-back never matches.
	older := testAuthorization("code-grant-a-old", firstClient.ID, user.ID, time.Now().Add(5*time.Minute))
	older.CreatedAt = time.Now().Add(-2 * time.Hour).Truncate(time.Microsecond)
	older.Scopes = model.StringArray{"openid"}
	if err := authorizations.Create(context.Background(), older); err != nil {
		t.Fatalf("Create(older) error = %v", err)
	}
	newer := testAuthorization("code-grant-a-new", firstClient.ID, user.ID, time.Now().Add(5*time.Minute))
	newer.CreatedAt = time.Now().Add(-1 * time.Hour).Truncate(time.Microsecond)
	newer.Scopes = model.StringArray{"openid", "profile"}
	if err := authorizations.Create(context.Background(), newer); err != nil {
		t.Fatalf("Create(newer) error = %v", err)
	}
	// Scopes come from the authorization row (what the user actually consented to),
	// not the client registration — the grant's scopes are the granted set.
	only := testAuthorization("code-grant-b", secondClient.ID, user.ID, time.Now().Add(5*time.Minute))
	only.CreatedAt = time.Now().Add(-30 * time.Minute).Truncate(time.Microsecond)
	only.Scopes = model.StringArray{"openid", "email"}
	if err := authorizations.Create(context.Background(), only); err != nil {
		t.Fatalf("Create(client B) error = %v", err)
	}
	// Another user consents to client A *after* user's newest consent, with a
	// different scope set. If the user_id filter regressed, DISTINCT ON would
	// surface this row instead and grantA's scopes / last_authorized_at would flip.
	intruder := testAuthorization("code-grant-a-intruder", firstClient.ID, otherUser.ID, time.Now().Add(5*time.Minute))
	intruder.CreatedAt = time.Now().Add(-30 * time.Minute).Truncate(time.Microsecond)
	intruder.Scopes = model.StringArray{"openid"}
	if err := authorizations.Create(context.Background(), intruder); err != nil {
		t.Fatalf("Create(other user consent) error = %v", err)
	}
	// A consent to the disabled client C, so the list has a grant to show there.
	disabledGrant := testAuthorization("code-grant-c", disabledClient.ID, user.ID, time.Now().Add(5*time.Minute))
	disabledGrant.CreatedAt = time.Now().Add(-15 * time.Minute).Truncate(time.Microsecond)
	if err := authorizations.Create(context.Background(), disabledGrant); err != nil {
		t.Fatalf("Create(client C consent) error = %v", err)
	}

	grants, err := authorizations.ListGrantsByUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("ListGrantsByUser() error = %v", err)
	}
	if len(grants) != 3 {
		t.Fatalf("grants = %d, want 3 (one per client)", len(grants))
	}

	var grantA *repository.OAuthGrant
	for i := range grants {
		if grants[i].ClientKey == firstClient.ClientID {
			grantA = &grants[i]
		}
	}
	if grantA == nil {
		t.Fatalf("grants = %+v, want client %s present", grants, firstClient.ClientID)
	}
	// The text[] columns must have scanned through model.StringArray...
	if len(grantA.RedirectURIs) != 1 || grantA.RedirectURIs[0] != "https://a.test/cb" {
		t.Fatalf("grantA.RedirectURIs = %v, want the scanned text[]", grantA.RedirectURIs)
	}
	// ...the DISTINCT ON must have surfaced the newer consent's scopes...
	if len(grantA.Scopes) != 2 || grantA.Scopes[0] != "openid" || grantA.Scopes[1] != "profile" {
		t.Fatalf("grantA.Scopes = %v, want the newer authorization's scopes", grantA.Scopes)
	}
	// ...and the user_id filter must have kept the other user's later consent out.
	if !grantA.LastAuthorizedAt.Equal(newer.CreatedAt) {
		t.Fatalf("grantA.LastAuthorizedAt = %v, want the user's own newer consent %v (other user's consent leaked)",
			grantA.LastAuthorizedAt, newer.CreatedAt)
	}

	var grantB *repository.OAuthGrant
	for i := range grants {
		if grants[i].ClientKey == secondClient.ClientID {
			grantB = &grants[i]
		}
	}
	if grantB == nil {
		t.Fatalf("grants = %+v, want client %s present", grants, secondClient.ClientID)
	}
	if len(grantB.RedirectURIs) != 2 || grantB.RedirectURIs[0] != "https://b.test/cb" || grantB.RedirectURIs[1] != "https://b.test/cb2" {
		t.Fatalf("grantB.RedirectURIs = %v, want both values scanned", grantB.RedirectURIs)
	}
	if len(grantB.Scopes) != 2 || grantB.Scopes[0] != "openid" || grantB.Scopes[1] != "email" {
		t.Fatalf("grantB.Scopes = %v, want both scanned", grantB.Scopes)
	}

	var grantC *repository.OAuthGrant
	for i := range grants {
		if grants[i].ClientKey == disabledClient.ClientID {
			grantC = &grants[i]
		}
	}
	if grantC == nil {
		t.Fatalf("grants = %+v, want the disabled client %s present", grants, disabledClient.ClientID)
	}
	if grantC.IsActive == nil || *grantC.IsActive {
		t.Fatalf("grantC.IsActive = %v, want an explicit false", grantC.IsActive)
	}
}

func TestOAuthAuthorizationRepositoryConsumeUnknownCode(t *testing.T) {
	database := setupDatabase(t)
	authorizations := repository.NewOAuthAuthorization(database)

	if _, err := authorizations.Consume(context.Background(), "code-missing", time.Now()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("Consume() error = %v, want ErrNotFound", err)
	}
}

func TestOAuthAuthorizationRepositoryRejectsInvalidArguments(t *testing.T) {
	database := setupDatabase(t)
	authorizations := repository.NewOAuthAuthorization(database)

	if err := authorizations.Create(context.Background(), nil); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("Create(nil) error = %v, want ErrInvalidArgument", err)
	}
	if err := authorizations.Create(context.Background(), &model.OAuthAuthorization{}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("Create(empty) error = %v, want ErrInvalidArgument", err)
	}
	if _, err := authorizations.Consume(context.Background(), "  ", time.Now()); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("Consume(blank) error = %v, want ErrInvalidArgument", err)
	}
	if _, err := authorizations.Consume(context.Background(), "code", time.Time{}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("Consume(zero time) error = %v, want ErrInvalidArgument", err)
	}
}

// V002 tightened the schema to S256-only; a plain challenge must be impossible to
// persist, so the protocol constraint cannot be bypassed by a repository caller.
func TestOAuthAuthorizationRepositoryRejectsPlainPKCEMethod(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "authz-plain@njupt.edu.cn")
	client := createOAuthClient(t, database)
	authorizations := repository.NewOAuthAuthorization(database)

	authorization := testAuthorization("code-plain", client.ID, user.ID, time.Now().Add(5*time.Minute))
	authorization.CodeChallengeMethod = "plain"
	if err := authorizations.Create(context.Background(), authorization); err == nil {
		t.Fatal("Create() accepted code_challenge_method=plain, want the V002 constraint to reject it")
	}
}

func assertAuthorizationUsed(t *testing.T, database *gorm.DB, code string, want bool) {
	t.Helper()
	var stored model.OAuthAuthorization
	if err := database.Where("code = ?", code).First(&stored).Error; err != nil {
		t.Fatalf("read authorization %q: %v", code, err)
	}
	if stored.IsUsed != want {
		t.Fatalf("authorization %q is_used = %v, want %v", code, stored.IsUsed, want)
	}
}
