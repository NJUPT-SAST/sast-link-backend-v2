package repository_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// registrationTokenPair builds the initial session rows for a registration under
// test. It mirrors what the session service's issuer produces, without signing:
// these tests exercise the transaction boundary, not token contents.
func registrationTokenPair(
	t *testing.T,
	database *gorm.DB,
	user *model.User,
) (*model.OAuthAccessToken, *model.OAuthRefreshToken, error) {
	t.Helper()
	client := createOAuthClient(t, database)
	familyID := "family-" + user.LoginEmail
	now := time.Now().UTC()
	access := &model.OAuthAccessToken{
		TokenID:   "jti-" + user.LoginEmail,
		ClientID:  client.ID,
		UserID:    user.ID,
		FamilyID:  &familyID,
		Scopes:    model.StringArray{"openid", "profile", "email"},
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
	refresh := &model.OAuthRefreshToken{
		TokenHash: "hash-" + user.LoginEmail,
		FamilyID:  familyID,
		Sequence:  0,
		ClientID:  client.ID,
		UserID:    user.ID,
		Scopes:    model.StringArray{"openid", "profile", "email"},
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
	return access, refresh, nil
}

func TestIdentityRepositoryUpdateProviderCredentials(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	identityRepository := repository.NewIdentity(database)
	user := createUserWithProfile(t, userRepository, "ghupdate@njupt.edu.cn")

	identity := &model.Identity{
		UserID:       user.ID,
		Provider:     model.LoginMethodGitHub,
		ProviderID:   "145339646",
		IdentityData: model.JSONB(`{"login":"old-handle"}`),
		AccessToken:  stringPtr("old-token"),
	}
	if err := identityRepository.CreateWithinLimit(context.Background(), identity, 1); err != nil {
		t.Fatalf("CreateWithinLimit() error = %v", err)
	}

	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	update := repository.IdentityCredentialUpdate{
		IdentityData:   model.JSONB(`{"login":"new-handle"}`),
		AccessToken:    stringPtr("new-token"),
		RefreshToken:   stringPtr("new-refresh"),
		TokenExpiresAt: &expires,
	}
	if err := identityRepository.UpdateProviderCredentials(context.Background(), identity.ID, update); err != nil {
		t.Fatalf("UpdateProviderCredentials() error = %v", err)
	}

	reloaded, err := identityRepository.FindByProviderID(context.Background(),
		model.LoginMethodGitHub, "145339646")
	if err != nil {
		t.Fatalf("FindByProviderID() error = %v", err)
	}
	// identity_data is replaced wholesale: a renamed GitHub handle must not leave
	// the old value behind. Compared as decoded JSON because PostgreSQL's jsonb
	// re-serializes with its own spacing.
	assertIdentityDataLogin(t, reloaded.IdentityData, "new-handle")
	if reloaded.AccessToken == nil || *reloaded.AccessToken != "new-token" {
		t.Fatalf("access_token = %v, want new-token", reloaded.AccessToken)
	}
	if reloaded.RefreshToken == nil || *reloaded.RefreshToken != "new-refresh" {
		t.Fatalf("refresh_token = %v, want new-refresh", reloaded.RefreshToken)
	}
	if reloaded.TokenExpiresAt == nil || !reloaded.TokenExpiresAt.Equal(expires) {
		t.Fatalf("token_expires_at = %v, want %v", reloaded.TokenExpiresAt, expires)
	}
	// The binding's owner and provider identity are not update targets.
	if reloaded.UserID != user.ID || reloaded.ProviderID != "145339646" {
		t.Fatalf("identity ownership changed: %#v", reloaded)
	}
}

func TestIdentityRepositoryUpdateProviderCredentialsLeavesDataWhenNil(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	identityRepository := repository.NewIdentity(database)
	user := createUserWithProfile(t, userRepository, "ghnil@njupt.edu.cn")

	identity := &model.Identity{
		UserID:       user.ID,
		Provider:     model.LoginMethodGitHub,
		ProviderID:   "700",
		IdentityData: model.JSONB(`{"login":"keep-me"}`),
	}
	if err := identityRepository.CreateWithinLimit(context.Background(), identity, 1); err != nil {
		t.Fatalf("CreateWithinLimit() error = %v", err)
	}

	// A nil IdentityData means the provider returned nothing worth storing;
	// blanking the column would lose display metadata for no reason.
	if err := identityRepository.UpdateProviderCredentials(context.Background(), identity.ID,
		repository.IdentityCredentialUpdate{AccessToken: stringPtr("t")}); err != nil {
		t.Fatalf("UpdateProviderCredentials() error = %v", err)
	}

	reloaded, err := identityRepository.FindByProviderID(context.Background(), model.LoginMethodGitHub, "700")
	if err != nil {
		t.Fatalf("FindByProviderID() error = %v", err)
	}
	assertIdentityDataLogin(t, reloaded.IdentityData, "keep-me")
}

// assertIdentityDataLogin checks the stored identity_data's login field.
// PostgreSQL stores jsonb in its own normalized form, so the column does not come
// back byte-identical to what was written.
func assertIdentityDataLogin(t *testing.T, raw model.JSONB, wantLogin string) {
	t.Helper()
	var decoded struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode identity_data %s: %v", raw, err)
	}
	if decoded.Login != wantLogin {
		t.Fatalf("identity_data login = %q, want %q", decoded.Login, wantLogin)
	}
}

func TestIdentityRepositoryUpdateProviderCredentialsRejectsUnknownRow(t *testing.T) {
	database := setupDatabase(t)
	identityRepository := repository.NewIdentity(database)

	err := identityRepository.UpdateProviderCredentials(context.Background(), 999999,
		repository.IdentityCredentialUpdate{AccessToken: stringPtr("t")})
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
	if err := identityRepository.UpdateProviderCredentials(context.Background(), 0,
		repository.IdentityCredentialUpdate{}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("error = %v, want ErrInvalidArgument", err)
	}
}

// Registering through a provider must commit the account and its binding
// together: a committed user with no identity would leave someone unable to log
// in the way they just registered.
func TestCreateRegistrationWithIdentityCommitsBothOrNeither(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	identityRepository := repository.NewIdentity(database)

	user := &model.User{
		Role:         model.UserRoleFreshman,
		State:        model.UserStateNJUPTer,
		College:      model.CollegeOther,
		Name:         "OAuth Registrant",
		PhoneNumber:  "13800138123",
		QQNumber:     "10001",
		PasswordHash: "hash",
		StudentID:    "B24049999",
		LoginEmail:   "oauthreg@njupt.edu.cn",
		Major:        "CS",
	}
	identity := &model.Identity{
		Provider:     model.LoginMethodGitHub,
		ProviderID:   "145339700",
		IdentityData: model.JSONB(`{"login":"registrant"}`),
		AccessToken:  stringPtr("gho_token"),
	}
	err := userRepository.CreateRegistrationWithIdentity(context.Background(), user, &model.Profile{}, identity,
		func(created *model.User) (*model.OAuthAccessToken, *model.OAuthRefreshToken, error) {
			return registrationTokenPair(t, database, created)
		})
	if err != nil {
		t.Fatalf("CreateRegistrationWithIdentity() error = %v", err)
	}
	if user.ID == 0 {
		t.Fatal("user ID was not populated")
	}
	// The owner is assigned inside the transaction, since the ID does not exist
	// until the user INSERT runs.
	if identity.UserID != user.ID {
		t.Fatalf("identity.UserID = %d, want %d", identity.UserID, user.ID)
	}

	bound, err := identityRepository.FindByProviderID(context.Background(),
		model.LoginMethodGitHub, "145339700")
	if err != nil {
		t.Fatalf("FindByProviderID() error = %v", err)
	}
	if bound.UserID != user.ID {
		t.Fatalf("binding owner = %d, want %d", bound.UserID, user.ID)
	}
}

// A failure after the user INSERT must roll the account back along with the
// binding, leaving the register ticket retryable.
func TestCreateRegistrationWithIdentityRollsBackOnTokenFailure(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	identityRepository := repository.NewIdentity(database)

	user := &model.User{
		Role:         model.UserRoleFreshman,
		State:        model.UserStateNJUPTer,
		College:      model.CollegeOther,
		Name:         "Rollback",
		PhoneNumber:  "13800138124",
		QQNumber:     "10002",
		PasswordHash: "hash",
		StudentID:    "B24049998",
		LoginEmail:   "oauthrollback@njupt.edu.cn",
		Major:        "CS",
	}
	identity := &model.Identity{
		Provider:   model.LoginMethodGitHub,
		ProviderID: "145339701",
	}
	wantErr := errors.New("signing failed")
	err := userRepository.CreateRegistrationWithIdentity(context.Background(), user, &model.Profile{}, identity,
		func(*model.User) (*model.OAuthAccessToken, *model.OAuthRefreshToken, error) {
			return nil, nil, wantErr
		})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want the factory failure", err)
	}

	if _, err := identityRepository.FindByProviderID(context.Background(),
		model.LoginMethodGitHub, "145339701"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("identity survived the rollback: %v", err)
	}
	if _, err := userRepository.FindByLoginEmail(context.Background(),
		"oauthrollback@njupt.edu.cn"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("user survived the rollback: %v", err)
	}
}

// A provider account already bound elsewhere must fail the registration rather
// than create a second binding: the V001 unique index is the backstop the
// service's pre-check relies on.
func TestCreateRegistrationWithIdentityRejectsBoundProviderAccount(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	identityRepository := repository.NewIdentity(database)

	owner := createUserWithProfile(t, userRepository, "ghowner@njupt.edu.cn")
	existing := &model.Identity{
		UserID:     owner.ID,
		Provider:   model.LoginMethodGitHub,
		ProviderID: "145339702",
	}
	if err := identityRepository.CreateWithinLimit(context.Background(), existing, 1); err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	user := &model.User{
		Role:         model.UserRoleFreshman,
		State:        model.UserStateNJUPTer,
		College:      model.CollegeOther,
		Name:         "Second",
		PhoneNumber:  "13800138125",
		QQNumber:     "10003",
		PasswordHash: "hash",
		StudentID:    "B24049997",
		LoginEmail:   "ghsecond@njupt.edu.cn",
		Major:        "CS",
	}
	err := userRepository.CreateRegistrationWithIdentity(context.Background(), user, &model.Profile{},
		&model.Identity{Provider: model.LoginMethodGitHub, ProviderID: "145339702"},
		func(created *model.User) (*model.OAuthAccessToken, *model.OAuthRefreshToken, error) {
			return registrationTokenPair(t, database, created)
		})
	if err == nil {
		t.Fatal("registration succeeded against an already-bound provider account")
	}
	if _, findErr := userRepository.FindByLoginEmail(context.Background(),
		"ghsecond@njupt.edu.cn"); !errors.Is(findErr, repository.ErrNotFound) {
		t.Fatalf("account was created despite the binding conflict: %v", findErr)
	}
}
