package repository_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func TestUserRepositoryCreateWithProfileIsAtomic(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)

	user := testUser("atomic@njupt.edu.cn")
	profile := &model.Profile{}
	if err := userRepository.CreateWithProfile(context.Background(), user, profile); err != nil {
		t.Fatalf("CreateWithProfile() error = %v", err)
	}
	if user.ID == 0 || profile.ID == 0 || profile.UserID != user.ID {
		t.Fatalf("created user/profile = %#v/%#v, want linked records", user, profile)
	}

	duplicate := testUser("atomic@njupt.edu.cn")
	duplicateProfile := &model.Profile{}
	if err := userRepository.CreateWithProfile(context.Background(), duplicate, duplicateProfile); err == nil {
		t.Fatal("CreateWithProfile() duplicate login_email error = nil")
	}
	var profileCount int64
	if err := database.Model(&model.Profile{}).Count(&profileCount).Error; err != nil {
		t.Fatalf("count profiles: %v", err)
	}
	if profileCount != 1 {
		t.Fatalf("profile count = %d, want 1 after failed transaction", profileCount)
	}
}

func TestUserRepositoryCreateWithProfileRejectsNilInputs(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)

	user := testUser("nil-profile@njupt.edu.cn")
	if err := userRepository.CreateWithProfile(context.Background(), user, nil); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("CreateWithProfile(user, nil) error = %v, want ErrInvalidArgument", err)
	}
	var userCount int64
	if err := database.Model(&model.User{}).Where("login_email = ?", user.LoginEmail).Count(&userCount).Error; err != nil {
		t.Fatalf("count user after nil profile: %v", err)
	}
	if userCount != 0 || user.ID != 0 {
		t.Fatalf("nil-profile user count/ID = %d/%d, want 0/0", userCount, user.ID)
	}

	profile := &model.Profile{}
	if err := userRepository.CreateWithProfile(context.Background(), nil, profile); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("CreateWithProfile(nil, profile) error = %v, want ErrInvalidArgument", err)
	}
	if profile.ID != 0 || profile.UserID != 0 {
		t.Fatalf("profile after nil user = %#v, want unmodified", profile)
	}
}

func TestUserRepositoryFindByLoginIdentifier(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "primary@njupt.edu.cn")
	for _, identity := range []model.Identity{
		{UserID: user.ID, Provider: model.LoginMethodOtherMail, ProviderID: "other@example.test"},
		{UserID: user.ID, Provider: model.LoginMethodGitHub, ProviderID: "github@example.test"},
		{UserID: user.ID, Provider: model.LoginMethodLark, ProviderID: "lark@example.test"},
	} {
		if err := database.Create(&identity).Error; err != nil {
			t.Fatalf("create %s identity: %v", identity.Provider, err)
		}
	}

	for _, identifier := range []string{"primary@njupt.edu.cn", "other@example.test"} {
		found, err := userRepository.FindByLoginIdentifier(context.Background(), identifier)
		if err != nil {
			t.Fatalf("FindByLoginIdentifier(%q) error = %v", identifier, err)
		}
		assertLoadedUser(t, found, user.ID)
	}
	for _, identifier := range []string{"github@example.test", "lark@example.test", "missing@example.test"} {
		_, err := userRepository.FindByLoginIdentifier(context.Background(), identifier)
		if !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("FindByLoginIdentifier(%q) error = %v, want ErrNotFound", identifier, err)
		}
	}

	found, err := userRepository.FindByID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	assertLoadedUser(t, found, user.ID)
	_, err = userRepository.FindByID(context.Background(), user.ID+100)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindByID(absent) error = %v, want ErrNotFound", err)
	}

	updateErr := database.Model(&model.User{}).Where("id = ?", user.ID).Update("token_version", 7).Error
	if updateErr != nil {
		t.Fatalf("update token_version: %v", updateErr)
	}
	authState, err := userRepository.FindAuthStateByID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("FindAuthStateByID() error = %v", err)
	}
	if authState.ID != user.ID || authState.State != model.UserStateNJUPTer || authState.TokenVersion != 7 {
		t.Fatalf("FindAuthStateByID() = %#v, want ID/state/token_version", authState)
	}
	_, err = userRepository.FindAuthStateByID(context.Background(), user.ID+100)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindAuthStateByID(absent) error = %v, want ErrNotFound", err)
	}
}

func TestUserRepositoryFindByLoginEmailAndExistenceChecks(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "lookup@njupt.edu.cn")

	found, err := userRepository.FindByLoginEmail(context.Background(), "lookup@njupt.edu.cn")
	if err != nil {
		t.Fatalf("FindByLoginEmail() error = %v", err)
	}
	if found.ID != user.ID || found.Profile == nil {
		t.Fatalf("FindByLoginEmail() = %#v, want user %d with profile", found, user.ID)
	}

	// FindByLoginEmail must not resolve other-mail identities, unlike
	// FindByLoginIdentifier: password reset targets the login email only.
	identityRepository := repository.NewIdentity(database)
	if err := identityRepository.CreateWithinLimit(context.Background(), &model.Identity{
		UserID:     user.ID,
		Provider:   model.LoginMethodOtherMail,
		ProviderID: "alias@qq.com",
	}, 2); err != nil {
		t.Fatalf("CreateWithinLimit() error = %v", err)
	}
	if _, err := userRepository.FindByLoginEmail(context.Background(), "alias@qq.com"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindByLoginEmail(other mail) error = %v, want ErrNotFound", err)
	}

	for _, test := range []struct {
		name  string
		check func() (bool, error)
		want  bool
	}{
		{"login email present", func() (bool, error) {
			return userRepository.ExistsByLoginEmail(context.Background(), "lookup@njupt.edu.cn")
		}, true},
		{"login email absent", func() (bool, error) {
			return userRepository.ExistsByLoginEmail(context.Background(), "nobody@njupt.edu.cn")
		}, false},
		{"student id present", func() (bool, error) {
			return userRepository.ExistsByStudentID(context.Background(), user.StudentID)
		}, true},
		{"student id absent", func() (bool, error) {
			return userRepository.ExistsByStudentID(context.Background(), "B0000000000")
		}, false},
	} {
		got, err := test.check()
		if err != nil {
			t.Fatalf("%s: error = %v", test.name, err)
		}
		if got != test.want {
			t.Fatalf("%s = %t, want %t", test.name, got, test.want)
		}
	}
}

// The password rewrite, the token_version bump and the session revocation must
// commit together: token_version alone does not stop refresh tokens, because the
// refresh flow never compares it.
func TestUserRepositoryUpdatePasswordAndRevokeSessions(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	tokenRepository := repository.NewToken(database)
	user := createUserWithProfile(t, userRepository, "rotate@njupt.edu.cn")
	client := createOAuthClient(t, database)
	createTokenPair(t, tokenRepository, "rotate-live", "family-rotate", 0, client.ID, user.ID)

	revokedAt := time.Now().UTC().Truncate(time.Millisecond)
	entries, err := userRepository.UpdatePasswordAndRevokeSessions(context.Background(), user.ID, "new-hash", revokedAt)
	if err != nil {
		t.Fatalf("UpdatePasswordAndRevokeSessions() error = %v", err)
	}
	if len(entries) != 1 || entries[0].TokenID != "rotate-live-access" {
		t.Fatalf("entries = %#v, want the live access token", entries)
	}

	var stored model.User
	if err := database.First(&stored, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if stored.PasswordHash != "new-hash" {
		t.Fatalf("password = %q, want new-hash", stored.PasswordHash)
	}
	if stored.TokenVersion != user.TokenVersion+1 {
		t.Fatalf("token_version = %d, want %d", stored.TokenVersion, user.TokenVersion+1)
	}
	assertTokenRevokedAt(t, database, "rotate-live-access", "rotate-live-refresh", revokedAt)

	var outboxCount int64
	if err := database.Model(&model.TokenBlacklistOutbox{}).
		Where("token_id = ?", "rotate-live-access").
		Count(&outboxCount).Error; err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	if outboxCount != 1 {
		t.Fatalf("outbox rows = %d, want 1", outboxCount)
	}
}

// Only live tokens need blacklist delivery; already-expired ones fall out of the
// entry set even though the row is still revoked.
func TestUserRepositoryUpdatePasswordSkipsExpiredTokens(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	tokenRepository := repository.NewToken(database)
	user := createUserWithProfile(t, userRepository, "expired@njupt.edu.cn")
	client := createOAuthClient(t, database)
	createTokenPair(t, tokenRepository, "expired", "family-expired", 0, client.ID, user.ID)

	// Move the revocation clock past the token's one-hour expiry. Truncate to
	// milliseconds so the value survives PostgreSQL's microsecond precision.
	revokedAt := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Millisecond)
	entries, err := userRepository.UpdatePasswordAndRevokeSessions(context.Background(), user.ID, "another-hash", revokedAt)
	if err != nil {
		t.Fatalf("UpdatePasswordAndRevokeSessions() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %#v, want none for expired tokens", entries)
	}
	assertTokenRevokedAt(t, database, "expired-access", "expired-refresh", revokedAt)
}

func TestTokenRepositoryRevokeAllByUserLeavesOtherUsersAlone(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	tokenRepository := repository.NewToken(database)
	target := createUserWithProfile(t, userRepository, "target@njupt.edu.cn")
	bystander := createUserWithProfile(t, userRepository, "bystander@njupt.edu.cn")
	client := createOAuthClient(t, database)
	createTokenPair(t, tokenRepository, "target", "family-target", 0, client.ID, target.ID)
	createTokenPair(t, tokenRepository, "bystander", "family-bystander", 0, client.ID, bystander.ID)

	revokedAt := time.Now().UTC().Truncate(time.Millisecond)
	entries, err := tokenRepository.RevokeAllByUser(context.Background(), target.ID, revokedAt)
	if err != nil {
		t.Fatalf("RevokeAllByUser() error = %v", err)
	}
	if len(entries) != 1 || entries[0].TokenID != "target-access" {
		t.Fatalf("entries = %#v, want only the target's access token", entries)
	}
	assertTokenRevokedAt(t, database, "target-access", "target-refresh", revokedAt)
	assertTokenUnrevoked(t, database, "bystander-access", "bystander-refresh")
}
