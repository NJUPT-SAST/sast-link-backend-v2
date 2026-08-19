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
// sql.Scanner and would fail this Scan on the first grant. The test also pins
// the JOIN against oauth_clients for the display fields, the user_id filter
// (another user's grant must not leak into the list), and that a disabled
// client's grant is still listed with an explicit is_active false.
func TestOAuthAuthorizationRepositoryListGrantsScansTextArraysAndJoinsClient(t *testing.T) {
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

	// Seed one grant per user-client pair, as the V008 primary key enforces.
	// created_at carries microsecond precision in PostgreSQL, so truncate the
	// source values or the round-tripped read-back never matches.
	now := time.Now()
	seedGrantA := &model.OAuthGrant{
		UserID:    user.ID,
		ClientID:  firstClient.ID,
		Scopes:    model.StringArray{"openid", "profile"},
		GrantedAt: now.Add(-1 * time.Hour).Truncate(time.Microsecond),
	}
	if err := database.Create(seedGrantA).Error; err != nil {
		t.Fatalf("Create(grant A) error = %v", err)
	}
	// Scopes come from the grant row (what the user actually consented to),
	// not the client registration — the grant's scopes are the granted set.
	seedGrantB := &model.OAuthGrant{
		UserID:    user.ID,
		ClientID:  secondClient.ID,
		Scopes:    model.StringArray{"openid", "email"},
		GrantedAt: now.Add(-30 * time.Minute).Truncate(time.Microsecond),
	}
	if err := database.Create(seedGrantB).Error; err != nil {
		t.Fatalf("Create(grant B) error = %v", err)
	}
	// A grant to the disabled client C, so the list has an entry to show there.
	seedGrantC := &model.OAuthGrant{
		UserID:    user.ID,
		ClientID:  disabledClient.ID,
		Scopes:    model.StringArray{"openid"},
		GrantedAt: now.Add(-15 * time.Minute).Truncate(time.Microsecond),
	}
	if err := database.Create(seedGrantC).Error; err != nil {
		t.Fatalf("Create(grant C) error = %v", err)
	}
	// Another user's grant to client A: if the user_id filter regressed, the
	// list would gain a row it must not show.
	intruder := &model.OAuthGrant{
		UserID:    otherUser.ID,
		ClientID:  firstClient.ID,
		Scopes:    model.StringArray{"openid"},
		GrantedAt: now.Add(-30 * time.Minute).Truncate(time.Microsecond),
	}
	if err := database.Create(intruder).Error; err != nil {
		t.Fatalf("Create(other user grant) error = %v", err)
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
	// ...scopes come from the grant row, not the client registration...
	if len(grantA.Scopes) != 2 || grantA.Scopes[0] != "openid" || grantA.Scopes[1] != "profile" {
		t.Fatalf("grantA.Scopes = %v, want the granted set", grantA.Scopes)
	}
	// ...and the user_id filter must have kept the other user's grant out.
	if !grantA.LastAuthorizedAt.Equal(seedGrantA.GrantedAt) {
		t.Fatalf("grantA.LastAuthorizedAt = %v, want the grant time %v", grantA.LastAuthorizedAt, seedGrantA.GrantedAt)
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

// CreateWithGrant persists the code and the consent grant in one transaction.
// Re-consenting the same client upserts the grant row rather than duplicating
// it, so the authorized-apps list keeps exactly one entry per client, carrying
// the latest scopes and grant time.
func TestOAuthAuthorizationRepositoryCreateWithGrantUpserts(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "authz-grant@njupt.edu.cn")
	client := createOAuthClient(t, database)
	authorizations := repository.NewOAuthAuthorization(database)

	// First consent: code and grant row created together.
	first := testAuthorization("code-grant-first", client.ID, user.ID, time.Now().Add(5*time.Minute))
	first.CreatedAt = time.Now().Truncate(time.Microsecond)
	first.Scopes = model.StringArray{"openid"}
	if err := authorizations.CreateWithGrant(context.Background(), first); err != nil {
		t.Fatalf("CreateWithGrant(first) error = %v", err)
	}

	// Re-consenting the same client upserts the grant: still one row, scopes and
	// grant time refreshed to the new decision. The code, by contrast, is a
	// fresh single-use row every consent.
	second := testAuthorization("code-grant-second", client.ID, user.ID, time.Now().Add(5*time.Minute))
	second.CreatedAt = first.CreatedAt.Add(1 * time.Minute)
	second.ExpiresAt = second.CreatedAt.Add(5 * time.Minute)
	second.Scopes = model.StringArray{"openid", "profile"}
	if err := authorizations.CreateWithGrant(context.Background(), second); err != nil {
		t.Fatalf("CreateWithGrant(second) error = %v", err)
	}

	var count int64
	if err := database.Model(&model.OAuthGrant{}).
		Where("user_id = ? AND client_id = ?", user.ID, client.ID).
		Count(&count).Error; err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if count != 1 {
		t.Fatalf("grant rows = %d, want 1 (upsert, not duplicate)", count)
	}

	var grant model.OAuthGrant
	if err := database.Where("user_id = ? AND client_id = ?", user.ID, client.ID).
		First(&grant).Error; err != nil {
		t.Fatalf("read grant: %v", err)
	}
	if len(grant.Scopes) != 2 || grant.Scopes[0] != "openid" || grant.Scopes[1] != "profile" {
		t.Fatalf("grant scopes = %v, want the newer consent's set", grant.Scopes)
	}
	if !grant.GrantedAt.Equal(second.CreatedAt) {
		t.Fatalf("grant.GrantedAt = %v, want the newer consent's time %v", grant.GrantedAt, second.CreatedAt)
	}

	// The authorized-apps list reflects the upserted grant.
	grants, err := authorizations.ListGrantsByUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("ListGrantsByUser() error = %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("grants = %d, want 1", len(grants))
	}
	if len(grants[0].Scopes) != 2 || grants[0].Scopes[0] != "openid" || grants[0].Scopes[1] != "profile" {
		t.Fatalf("list scopes = %v, want the newer consent's set", grants[0].Scopes)
	}
}

// DeleteByUserClient drops both the consent grant and any in-flight
// authorization codes for the user-client pair, so a revoke both removes the
// application from the authorized-apps list and makes an unredeemed code
// unexchangeable.
func TestOAuthAuthorizationRepositoryDeleteByUserClientClearsBothTables(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "authz-revoke@njupt.edu.cn")
	client := createOAuthClient(t, database)
	authorizations := repository.NewOAuthAuthorization(database)

	authorization := testAuthorization("code-revoke-grant", client.ID, user.ID, time.Now().Add(5*time.Minute))
	authorization.CreatedAt = time.Now().Truncate(time.Microsecond)
	if err := authorizations.CreateWithGrant(context.Background(), authorization); err != nil {
		t.Fatalf("CreateWithGrant() error = %v", err)
	}

	if err := authorizations.DeleteByUserClient(context.Background(), user.ID, client.ID); err != nil {
		t.Fatalf("DeleteByUserClient() error = %v", err)
	}

	var grantCount int64
	if err := database.Model(&model.OAuthGrant{}).
		Where("user_id = ? AND client_id = ?", user.ID, client.ID).
		Count(&grantCount).Error; err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if grantCount != 0 {
		t.Fatalf("grant rows = %d, want 0 after revoke", grantCount)
	}

	// The in-flight code is gone too: consuming it must report not-found rather
	// than issuing a token from a code the revoke was supposed to kill.
	if _, err := authorizations.Consume(context.Background(), "code-revoke-grant", time.Now()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("Consume() after revoke = %v, want ErrNotFound", err)
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
