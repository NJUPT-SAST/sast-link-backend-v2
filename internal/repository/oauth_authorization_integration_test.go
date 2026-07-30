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
