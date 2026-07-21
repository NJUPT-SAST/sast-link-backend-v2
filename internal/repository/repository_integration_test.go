package repository_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/migration"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
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

func TestTokenRepositoryCreatePairAndFindRefreshToken(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "tokens@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "token-pair-family"
	access := accessToken("token-pair-access", client.ID, user.ID, &familyID)
	refresh := refreshToken("token-pair-refresh", familyID, 0, client.ID, user.ID)

	if err := tokenRepository.CreatePair(context.Background(), access, refresh); err != nil {
		t.Fatalf("CreatePair() error = %v", err)
	}
	if access.ID == 0 || refresh.ID == 0 {
		t.Fatalf("CreatePair() IDs = %d, %d; want persisted records", access.ID, refresh.ID)
	}
	found, err := tokenRepository.FindRefreshToken(context.Background(), refresh.TokenHash)
	if err != nil {
		t.Fatalf("FindRefreshToken() error = %v", err)
	}
	if found.ID != refresh.ID || found.TokenHash != refresh.TokenHash {
		t.Fatalf("FindRefreshToken() = %#v, want %#v", found, refresh)
	}
	foundAccess, err := tokenRepository.FindAccessTokenByJTI(context.Background(), access.TokenID)
	if err != nil {
		t.Fatalf("FindAccessTokenByJTI() error = %v", err)
	}
	if foundAccess.ID != access.ID || foundAccess.TokenID != access.TokenID {
		t.Fatalf("FindAccessTokenByJTI() = %#v, want %#v", foundAccess, access)
	}
	_, err = tokenRepository.FindAccessTokenByJTI(context.Background(), "absent-access-jti")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindAccessTokenByJTI(absent) error = %v, want ErrNotFound", err)
	}
	_, err = tokenRepository.FindRefreshToken(context.Background(), "absent-token-hash")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindRefreshToken(absent) error = %v, want ErrNotFound", err)
	}

	duplicateAccess := accessToken("rolled-back-access", client.ID, user.ID, &familyID)
	duplicateRefresh := refreshToken(refresh.TokenHash, familyID, 1, client.ID, user.ID)
	if err := tokenRepository.CreatePair(context.Background(), duplicateAccess, duplicateRefresh); err == nil {
		t.Fatal("CreatePair() duplicate refresh token hash error = nil")
	}
	var accessCount int64
	if err := database.Where("token_id = ?", duplicateAccess.TokenID).Model(&model.OAuthAccessToken{}).Count(&accessCount).Error; err != nil {
		t.Fatalf("count rolled-back access token: %v", err)
	}
	if accessCount != 0 {
		t.Fatalf("rolled-back access-token count = %d, want 0", accessCount)
	}
}

func TestTokenRepositoryCreatePairRejectsMismatchedPair(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "token-mismatch@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)

	tests := []struct {
		name   string
		mutate func(*model.OAuthAccessToken, *model.OAuthRefreshToken)
	}{
		{
			name: "family",
			mutate: func(_ *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				refresh.FamilyID = "different-family"
			},
		},
		{
			name: "client",
			mutate: func(_ *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				refresh.ClientID++
			},
		},
		{
			name: "user",
			mutate: func(_ *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				refresh.UserID++
			},
		},
		{
			name: "scope",
			mutate: func(access *model.OAuthAccessToken, _ *model.OAuthRefreshToken) {
				access.Scopes = model.StringArray{"openid", "email"}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			familyID := "mismatch-" + test.name
			access := accessToken(test.name+"-access", client.ID, user.ID, &familyID)
			refresh := refreshToken(test.name+"-refresh", familyID, 0, client.ID, user.ID)
			test.mutate(access, refresh)

			if err := tokenRepository.CreatePair(context.Background(), access, refresh); err == nil {
				t.Fatal("CreatePair() error = nil, want mismatched pair rejection")
			}

			var accessCount int64
			if err := database.Model(&model.OAuthAccessToken{}).
				Where("token_id = ?", access.TokenID).
				Count(&accessCount).Error; err != nil {
				t.Fatalf("count access token: %v", err)
			}
			if accessCount != 0 {
				t.Fatalf("access-token count = %d, want 0", accessCount)
			}
		})
	}
}

func TestTokenRepositoryRotateRefreshToken(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotate@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotate-family"
	createTokenPair(t, tokenRepository, "rotate-current", familyID, 0, client.ID, user.ID)

	before := time.Now().UTC()
	newAccess := accessToken("rotate-new-access", client.ID, user.ID, &familyID)
	newRefresh := refreshToken("rotate-new-refresh", familyID, 1, client.ID, user.ID)
	if err := tokenRepository.RotateRefreshToken(
		context.Background(),
		"rotate-current-refresh",
		newAccess,
		newRefresh,
		before,
	); err != nil {
		t.Fatalf("RotateRefreshToken() error = %v", err)
	}
	after := time.Now().UTC()
	assertAccessTokenUnrevoked(t, database, "rotate-current-access")
	assertRefreshTokenRevokedBetween(t, database, "rotate-current-refresh", before, after)
	assertTokenUnrevoked(t, database, "rotate-new-access", "rotate-new-refresh")
}

func TestTokenRepositoryRotateRefreshTokenRejectsInvalidInputs(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotate-invalid@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotate-invalid-family"
	createTokenPair(t, tokenRepository, "rotate-invalid-current", familyID, 3, client.ID, user.ID)

	tests := []struct {
		name        string
		mutate      func(*model.OAuthAccessToken, *model.OAuthRefreshToken)
		want        error
		currentHash string
	}{
		{
			name:        "missing current",
			want:        repository.ErrNotFound,
			currentHash: "missing-refresh-hash",
		},
		{
			name:        "family mismatch",
			currentHash: "rotate-invalid-current-refresh",
			want:        repository.ErrInvalidArgument,
			mutate: func(access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				otherFamily := "other-family"
				access.FamilyID = &otherFamily
				refresh.FamilyID = otherFamily
			},
		},
		{
			name:        "client mismatch",
			currentHash: "rotate-invalid-current-refresh",
			want:        repository.ErrInvalidArgument,
			mutate: func(access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				access.ClientID++
				refresh.ClientID++
			},
		},
		{
			name:        "user mismatch",
			currentHash: "rotate-invalid-current-refresh",
			want:        repository.ErrInvalidArgument,
			mutate: func(access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				access.UserID++
				refresh.UserID++
			},
		},
		{
			name:        "sequence mismatch",
			currentHash: "rotate-invalid-current-refresh",
			want:        repository.ErrInvalidArgument,
			mutate: func(_ *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				refresh.Sequence = 5
			},
		},
		{
			name:        "scope escalation",
			currentHash: "rotate-invalid-current-refresh",
			want:        repository.ErrInvalidArgument,
			mutate: func(access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				access.Scopes = model.StringArray{"openid", "email"}
				refresh.Scopes = model.StringArray{"openid", "email"}
			},
		},
	}

	if err := tokenRepository.RotateRefreshToken(
		context.Background(),
		"rotate-invalid-current-refresh",
		accessToken("zero-time-access", client.ID, user.ID, &familyID),
		refreshToken("zero-time-refresh", familyID, 4, client.ID, user.ID),
		time.Time{},
	); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("RotateRefreshToken(zero revoked time) error = %v, want ErrInvalidArgument", err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			access := accessToken(test.name+"-access", client.ID, user.ID, &familyID)
			refresh := refreshToken(test.name+"-refresh", familyID, 4, client.ID, user.ID)
			if test.mutate != nil {
				test.mutate(access, refresh)
			}

			err := tokenRepository.RotateRefreshToken(context.Background(), test.currentHash, access, refresh, time.Now())
			if !errors.Is(err, test.want) {
				t.Fatalf("RotateRefreshToken() error = %v, want %v", err, test.want)
			}
			assertTokenPairAbsent(t, database, access.TokenID, refresh.TokenHash)
		})
	}
}

func TestTokenRepositoryRotateRefreshTokenReplayRevokesFamilyAndReturnsReplay(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotate-replay@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotate-replay-family"
	createTokenPair(t, tokenRepository, "rotate-replay-current", familyID, 0, client.ID, user.ID)
	createTokenPair(t, tokenRepository, "rotate-replay-active", familyID, 1, client.ID, user.ID)

	oldRevokedAt := time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC)
	if err := database.Model(&model.OAuthAccessToken{}).
		Where("token_id = ?", "rotate-replay-current-access").
		Update("revoked_at", oldRevokedAt).Error; err != nil {
		t.Fatalf("pre-revoke access token: %v", err)
	}
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("token_hash = ?", "rotate-replay-current-refresh").
		Update("revoked_at", oldRevokedAt).Error; err != nil {
		t.Fatalf("pre-revoke refresh token: %v", err)
	}

	newAccess := accessToken("rotate-replay-new-access", client.ID, user.ID, &familyID)
	newRefresh := refreshToken("rotate-replay-new-refresh", familyID, 1, client.ID, user.ID)
	beforeReplay := time.Now().UTC()
	err := tokenRepository.RotateRefreshToken(context.Background(), "rotate-replay-current-refresh", newAccess, newRefresh, beforeReplay)
	if !errors.Is(err, repository.ErrTokenReplay) {
		t.Fatalf("RotateRefreshToken(replay) error = %v, want ErrTokenReplay", err)
	}
	afterReplay := time.Now().UTC()
	assertTokenPairAbsent(t, database, newAccess.TokenID, newRefresh.TokenHash)
	assertTokenRevokedAt(t, database, "rotate-replay-current-access", "rotate-replay-current-refresh", oldRevokedAt)
	assertTokenRevokedBetween(t, database, "rotate-replay-active-access", "rotate-replay-active-refresh", beforeReplay, afterReplay)
}

func TestTokenRepositoryRotateRefreshTokenRejectsExpiredCurrent(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotate-expired@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotate-expired-family"
	createTokenPair(t, tokenRepository, "rotate-expired-current", familyID, 0, client.ID, user.ID)

	if err := database.Exec(`
		ALTER TABLE oauth_refresh_tokens
		DROP CONSTRAINT ck_oauth_refresh_tokens_expiry
	`).Error; err != nil {
		t.Fatalf("drop refresh expiry constraint: %v", err)
	}
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("token_hash = ?", "rotate-expired-current-refresh").
		Update("expires_at", time.Now().Add(-time.Hour)).Error; err != nil {
		t.Fatalf("expire current refresh token: %v", err)
	}

	newAccess := accessToken("rotate-expired-new-access", client.ID, user.ID, &familyID)
	newRefresh := refreshToken("rotate-expired-new-refresh", familyID, 1, client.ID, user.ID)
	err := tokenRepository.RotateRefreshToken(context.Background(), "rotate-expired-current-refresh", newAccess, newRefresh, time.Now())
	if !errors.Is(err, repository.ErrTokenExpired) {
		t.Fatalf("RotateRefreshToken(expired) error = %v, want ErrTokenExpired", err)
	}
	assertTokenPairAbsent(t, database, newAccess.TokenID, newRefresh.TokenHash)
}

func TestTokenRepositoryRevokeFamily(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "revoke@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyA := "family-a"
	familyB := "family-b"
	createTokenPair(t, tokenRepository, "a1", familyA, 0, client.ID, user.ID)
	createTokenPair(t, tokenRepository, "a2", familyA, 1, client.ID, user.ID)
	createTokenPair(t, tokenRepository, "b1", familyB, 0, client.ID, user.ID)

	revokedAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	if err := tokenRepository.RevokeFamily(context.Background(), familyA, revokedAt); err != nil {
		t.Fatalf("RevokeFamily() error = %v", err)
	}
	assertFamilyRevokedAt(t, database, familyA, revokedAt)
	assertFamilyUnrevoked(t, database, familyB)

	preservedAt := revokedAt.Add(-time.Hour)
	if err := database.Model(&model.OAuthAccessToken{}).Where("token_id = ?", "a1-access").Update("revoked_at", preservedAt).Error; err != nil {
		t.Fatalf("pre-revoke access token: %v", err)
	}
	if err := database.Model(&model.OAuthRefreshToken{}).Where("token_hash = ?", "a1-refresh").Update("revoked_at", preservedAt).Error; err != nil {
		t.Fatalf("pre-revoke refresh token: %v", err)
	}
	if err := tokenRepository.RevokeFamily(context.Background(), familyA, revokedAt.Add(time.Hour)); err != nil {
		t.Fatalf("second RevokeFamily() error = %v", err)
	}
	assertTokenRevokedAt(t, database, "a1-access", "a1-refresh", preservedAt)
}

func TestAuditLogRepositoryCreate(t *testing.T) {
	database := setupDatabase(t)
	auditLogRepository := repository.NewAuditLog(database)
	entry := &model.AuditLog{
		Action:   "login",
		Resource: "user",
		Detail:   model.JSONB(`{"provider":"password","success":true}`),
	}

	if err := auditLogRepository.Create(context.Background(), entry); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	var found model.AuditLog
	if err := database.First(&found, entry.ID).Error; err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if found.UserID != nil || found.Action != entry.Action || found.Resource != entry.Resource ||
		found.Success == nil || !*found.Success || entry.Success == nil || !*entry.Success ||
		!jsonEqual(found.Detail, entry.Detail) {
		t.Fatalf("audit log = %#v, want persisted default success and detail %s", found, entry.Detail)
	}

	falseValue := false
	failed := &model.AuditLog{Action: "login", Resource: "user", Success: &falseValue}
	if err := auditLogRepository.Create(context.Background(), failed); err != nil {
		t.Fatalf("Create(failed) error = %v", err)
	}
	var foundFailed model.AuditLog
	if err := database.First(&foundFailed, failed.ID).Error; err != nil {
		t.Fatalf("read failed audit log: %v", err)
	}
	if foundFailed.Success == nil || *foundFailed.Success {
		t.Fatalf("failed audit Success = %v, want false", foundFailed.Success)
	}

	invalid := &model.AuditLog{Action: strings.Repeat("a", 51), Resource: "user"}
	if err := auditLogRepository.Create(context.Background(), invalid); err == nil ||
		!strings.Contains(err.Error(), "create audit log") {
		t.Fatalf("Create(invalid) error = %v, want wrapped create audit log failure", err)
	}
}

func setupDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	databaseURL := testutil.StartPostgres(t)
	instance, err := migration.New(databaseURL)
	if err != nil {
		t.Fatalf("create migration: %v", err)
	}
	t.Cleanup(func() { _, _ = instance.Close() })
	if err := instance.Up(); err != nil {
		t.Fatalf("apply V001: %v", err)
	}
	return testutil.OpenGORM(t, databaseURL)
}

func testUser(loginEmail string) *model.User {
	return &model.User{
		Name:         "Repository Test User",
		PhoneNumber:  "13800138000",
		QQNumber:     "10000",
		PasswordHash: "password-hash",
		LoginEmail:   loginEmail,
		StudentID:    "B" + loginEmail[:strings.IndexByte(loginEmail, '@')],
		Role:         model.UserRoleFreshman,
		State:        model.UserStateNJUPTer,
		EmailType:    model.EmailTypeNJUpt,
		College:      model.CollegeOther,
	}
}

func createUserWithProfile(t *testing.T, userRepository *repository.UserRepository, loginEmail string) *model.User {
	t.Helper()
	user := testUser(loginEmail)
	if err := userRepository.CreateWithProfile(context.Background(), user, &model.Profile{}); err != nil {
		t.Fatalf("CreateWithProfile(%q) error = %v", loginEmail, err)
	}
	return user
}

func createOAuthClient(t *testing.T, database *gorm.DB) *model.OAuthClient {
	t.Helper()
	client := &model.OAuthClient{
		ClientID:     "repository-test-client",
		ClientName:   "Repository Test Client",
		ClientType:   model.ClientTypeFirstParty,
		RedirectURIs: model.StringArray{"https://example.test/callback"},
		GrantTypes:   model.StringArray{"authorization_code", "refresh_token"},
		Scopes:       model.StringArray{"openid"},
	}
	if err := database.Create(client).Error; err != nil {
		t.Fatalf("create OAuth client: %v", err)
	}
	if client.IsActive == nil || !*client.IsActive {
		t.Fatalf("OAuth client IsActive = %v, want default true", client.IsActive)
	}
	return client
}

func accessToken(tokenID string, clientID int64, userID int64, familyID *string) *model.OAuthAccessToken {
	return &model.OAuthAccessToken{
		TokenID:   tokenID,
		ClientID:  clientID,
		UserID:    userID,
		FamilyID:  familyID,
		Scopes:    model.StringArray{"openid"},
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func refreshToken(tokenHash string, familyID string, sequence int, clientID int64, userID int64) *model.OAuthRefreshToken {
	return &model.OAuthRefreshToken{
		TokenHash: tokenHash,
		FamilyID:  familyID,
		Sequence:  sequence,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    model.StringArray{"openid"},
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func createTokenPair(
	t *testing.T,
	tokenRepository *repository.TokenRepository,
	prefix string,
	familyID string,
	sequence int,
	clientID int64,
	userID int64,
) {
	t.Helper()
	if err := tokenRepository.CreatePair(
		context.Background(),
		accessToken(prefix+"-access", clientID, userID, &familyID),
		refreshToken(prefix+"-refresh", familyID, sequence, clientID, userID),
	); err != nil {
		t.Fatalf("CreatePair(%q) error = %v", prefix, err)
	}
}

func assertLoadedUser(t *testing.T, user *model.User, userID int64) {
	t.Helper()
	if user.ID != userID || user.Profile == nil || len(user.Identities) != 3 {
		t.Fatalf("user = %#v, want ID %d with profile and 3 identities", user, userID)
	}
}

func assertFamilyRevokedAt(t *testing.T, database *gorm.DB, familyID string, want time.Time) {
	t.Helper()
	var accessTokens []model.OAuthAccessToken
	if err := database.Where("family_id = ?", familyID).Find(&accessTokens).Error; err != nil {
		t.Fatalf("read access tokens for %q: %v", familyID, err)
	}
	var refreshTokens []model.OAuthRefreshToken
	if err := database.Where("family_id = ?", familyID).Find(&refreshTokens).Error; err != nil {
		t.Fatalf("read refresh tokens for %q: %v", familyID, err)
	}
	if len(accessTokens) != 2 || len(refreshTokens) != 2 {
		t.Fatalf("family %q records = %d access, %d refresh; want 2 each", familyID, len(accessTokens), len(refreshTokens))
	}
	for _, token := range accessTokens {
		if token.RevokedAt == nil || !token.RevokedAt.Equal(want) {
			t.Fatalf("access token %q RevokedAt = %v, want %v", token.TokenID, token.RevokedAt, want)
		}
	}
	for _, token := range refreshTokens {
		if token.RevokedAt == nil || !token.RevokedAt.Equal(want) {
			t.Fatalf("refresh token %q RevokedAt = %v, want %v", token.TokenHash, token.RevokedAt, want)
		}
	}
}

func assertFamilyUnrevoked(t *testing.T, database *gorm.DB, familyID string) {
	t.Helper()
	var access model.OAuthAccessToken
	if err := database.Where("family_id = ?", familyID).First(&access).Error; err != nil {
		t.Fatalf("read access token for %q: %v", familyID, err)
	}
	var refresh model.OAuthRefreshToken
	if err := database.Where("family_id = ?", familyID).First(&refresh).Error; err != nil {
		t.Fatalf("read refresh token for %q: %v", familyID, err)
	}
	if access.RevokedAt != nil || refresh.RevokedAt != nil {
		t.Fatalf("family %q revocation = %v / %v, want nil", familyID, access.RevokedAt, refresh.RevokedAt)
	}
}

func assertTokenUnrevoked(t *testing.T, database *gorm.DB, tokenID string, tokenHash string) {
	t.Helper()
	var access model.OAuthAccessToken
	if err := database.Where("token_id = ?", tokenID).First(&access).Error; err != nil {
		t.Fatalf("read access token %q: %v", tokenID, err)
	}
	var refresh model.OAuthRefreshToken
	if err := database.Where("token_hash = ?", tokenHash).First(&refresh).Error; err != nil {
		t.Fatalf("read refresh token %q: %v", tokenHash, err)
	}
	if access.RevokedAt != nil || refresh.RevokedAt != nil {
		t.Fatalf("revocations = %v / %v, want nil", access.RevokedAt, refresh.RevokedAt)
	}
}

func assertAccessTokenUnrevoked(t *testing.T, database *gorm.DB, tokenID string) {
	t.Helper()
	var access model.OAuthAccessToken
	if err := database.Where("token_id = ?", tokenID).First(&access).Error; err != nil {
		t.Fatalf("read access token %q: %v", tokenID, err)
	}
	if access.RevokedAt != nil {
		t.Fatalf("access token %q RevokedAt = %v, want nil", tokenID, access.RevokedAt)
	}
}

func assertRefreshTokenRevokedBetween(t *testing.T, database *gorm.DB, tokenHash string, earliest time.Time, latest time.Time) {
	t.Helper()
	var refresh model.OAuthRefreshToken
	if err := database.Where("token_hash = ?", tokenHash).First(&refresh).Error; err != nil {
		t.Fatalf("read refresh token %q: %v", tokenHash, err)
	}
	if refresh.RevokedAt == nil || refresh.RevokedAt.Before(earliest) || refresh.RevokedAt.After(latest.Add(time.Second)) {
		t.Fatalf("refresh token %q RevokedAt = %v, want between %v and %v", tokenHash, refresh.RevokedAt, earliest, latest)
	}
}

func assertTokenRevokedBetween(t *testing.T, database *gorm.DB, tokenID string, tokenHash string, earliest time.Time, latest time.Time) {
	t.Helper()
	var access model.OAuthAccessToken
	if err := database.Where("token_id = ?", tokenID).First(&access).Error; err != nil {
		t.Fatalf("read access token %q: %v", tokenID, err)
	}
	var refresh model.OAuthRefreshToken
	if err := database.Where("token_hash = ?", tokenHash).First(&refresh).Error; err != nil {
		t.Fatalf("read refresh token %q: %v", tokenHash, err)
	}
	latest = latest.Add(time.Second)
	if access.RevokedAt == nil || access.RevokedAt.Before(earliest) || access.RevokedAt.After(latest) ||
		refresh.RevokedAt == nil || refresh.RevokedAt.Before(earliest) || refresh.RevokedAt.After(latest) {
		t.Fatalf("revocations = %v / %v, want between %v and %v", access.RevokedAt, refresh.RevokedAt, earliest, latest)
	}
}

func assertTokenRevokedAt(t *testing.T, database *gorm.DB, tokenID string, tokenHash string, want time.Time) {
	t.Helper()
	var access model.OAuthAccessToken
	if err := database.Where("token_id = ?", tokenID).First(&access).Error; err != nil {
		t.Fatalf("read access token %q: %v", tokenID, err)
	}
	var refresh model.OAuthRefreshToken
	if err := database.Where("token_hash = ?", tokenHash).First(&refresh).Error; err != nil {
		t.Fatalf("read refresh token %q: %v", tokenHash, err)
	}
	if access.RevokedAt == nil || !access.RevokedAt.Equal(want) || refresh.RevokedAt == nil || !refresh.RevokedAt.Equal(want) {
		t.Fatalf("revocations = %v / %v, want %v", access.RevokedAt, refresh.RevokedAt, want)
	}
}

func jsonEqual(left model.JSONB, right model.JSONB) bool {
	var leftValue any
	if err := json.Unmarshal(left, &leftValue); err != nil {
		return false
	}
	var rightValue any
	if err := json.Unmarshal(right, &rightValue); err != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}
