package repository_test

import (
	"context"
	"encoding/json"
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

func setupDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	databaseURL := testutil.SharedPostgresURL(t)
	instance, err := migration.New(databaseURL)
	if err != nil {
		t.Fatalf("create migration: %v", err)
	}
	t.Cleanup(func() { _, _ = instance.Close() })
	if upErr := instance.Up(); upErr != nil {
		t.Fatalf("apply migrations: %v", upErr)
	}
	database := testutil.OpenGORM(t, databaseURL)
	// The shared container no longer disappears between tests, so the GORM
	// connection pool must be closed explicitly; otherwise its idle connections
	// accumulate across tests and exhaust the container's max_connections.
	sqlDB, err := database.DB()
	if err != nil {
		t.Fatalf("unwrap GORM connection pool: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return database
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

func boolPtr(value bool) *bool {
	return &value
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
	// The DB stores timestamps at microsecond precision and truncates on write,
	// while earliest is a nanosecond-precision time.Now(). A revocation written in
	// the same clock tick can therefore read back up to 1µs earlier than earliest;
	// widen the lower bound by that truncation window. The upper bound keeps its
	// existing one-second slack for scheduling jitter.
	earliest = earliest.Add(-time.Microsecond)
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
