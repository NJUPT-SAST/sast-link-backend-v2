package model_test

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/migration"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
	"gorm.io/gorm"
)

func TestUserTableName(t *testing.T) {
	if got := (model.User{}).TableName(); got != "user" {
		t.Fatalf("TableName() = %q, want user", got)
	}
}

func TestModelRoundTripPreservesNullableAndPostgresTypes(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	migrateV1(t, databaseURL)
	database := testutil.OpenGORM(t, databaseURL)

	user := model.User{
		Name:         "Test User",
		PhoneNumber:  "13800138000",
		QQNumber:     "10000",
		PasswordHash: "password-hash",
		LoginEmail:   "user@njupt.edu.cn",
		Role:         model.UserRoleFreshman,
		State:        model.UserStateNJUPTer,
		EmailType:    model.EmailTypeNJUpt,
		College:      model.CollegeOther,
		Major:        "",
	}
	if err := database.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	profile := model.Profile{UserID: user.ID}
	if err := database.Create(&profile).Error; err != nil {
		t.Fatalf("create profile: %v", err)
	}
	identity := model.Identity{
		UserID:     user.ID,
		Provider:   model.LoginMethodGitHub,
		ProviderID: "github-user",
	}
	if err := database.Create(&identity).Error; err != nil {
		t.Fatalf("create identity: %v", err)
	}
	client := model.OAuthClient{
		ClientID:     "test-client",
		ClientName:   "Test Client",
		ClientType:   model.ClientTypeFirstParty,
		RedirectURIs: model.StringArray{"https://example.test/callback,query", `quote"here`, `slash\here`, ""},
		GrantTypes:   model.StringArray{"authorization_code", "refresh_token"},
		Scopes:       model.StringArray{"openid", "profile"},
	}
	if err := database.Create(&client).Error; err != nil {
		t.Fatalf("create OAuth client: %v", err)
	}

	var gotUser model.User
	if err := database.First(&gotUser, user.ID).Error; err != nil {
		t.Fatalf("read user: %v", err)
	}
	if gotUser.StudentID != nil {
		t.Fatalf("StudentID = %q, want nil", *gotUser.StudentID)
	}
	var gotProfile model.Profile
	if err := database.First(&gotProfile, profile.ID).Error; err != nil {
		t.Fatalf("read profile: %v", err)
	}
	assertNilProfileFields(t, gotProfile)
	var gotIdentity model.Identity
	if err := database.First(&gotIdentity, identity.ID).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if gotIdentity.IdentityData != nil {
		t.Fatalf("IdentityData = %s, want nil", gotIdentity.IdentityData)
	}
	var gotClient model.OAuthClient
	if err := database.First(&gotClient, client.ID).Error; err != nil {
		t.Fatalf("read OAuth client: %v", err)
	}
	if gotClient.ClientSecretHash != nil {
		t.Fatalf("ClientSecretHash = %q, want nil", *gotClient.ClientSecretHash)
	}
	assertOAuthModelMappings(t, database, user.ID, client.ID)
	if !reflect.DeepEqual(gotClient.RedirectURIs, client.RedirectURIs) {
		t.Fatalf("RedirectURIs = %q, want %q", gotClient.RedirectURIs, client.RedirectURIs)
	}
	if !reflect.DeepEqual(gotClient.GrantTypes, client.GrantTypes) {
		t.Fatalf("GrantTypes = %q, want %q", gotClient.GrantTypes, client.GrantTypes)
	}
	if !reflect.DeepEqual(gotClient.Scopes, client.Scopes) {
		t.Fatalf("Scopes = %q, want %q", gotClient.Scopes, client.Scopes)
	}
}

func TestStringArrayDistinguishesNullAndEmpty(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	migrateV1(t, databaseURL)
	database := testutil.OpenGORM(t, databaseURL)

	if err := database.Exec(`CREATE TABLE string_array_values (id BIGSERIAL PRIMARY KEY, values TEXT[])`).Error; err != nil {
		t.Fatalf("create string-array test table: %v", err)
	}
	if err := database.Exec(`INSERT INTO string_array_values (values) VALUES (NULL), ('{}'::text[])`).Error; err != nil {
		t.Fatalf("insert null and empty arrays: %v", err)
	}

	type stringArrayValue struct {
		ID     int64
		Values model.StringArray `gorm:"type:text[]"`
	}

	var values []stringArrayValue
	if err := database.Table("string_array_values").Order("id").Find(&values).Error; err != nil {
		t.Fatalf("read null and empty arrays: %v", err)
	}
	if len(values) != 2 {
		t.Fatalf("row count = %d, want 2", len(values))
	}
	if values[0].Values != nil {
		t.Fatalf("NULL text[] = %#v, want nil", values[0].Values)
	}
	if values[1].Values == nil || len(values[1].Values) != 0 {
		t.Fatalf("empty text[] = %#v, want non-nil empty slice", values[1].Values)
	}
}

func assertOAuthModelMappings(t *testing.T, database *gorm.DB, userID int64, clientID int64) {
	t.Helper()

	authorization := model.OAuthAuthorization{
		Code:                "authorization-code",
		ClientID:            clientID,
		UserID:              userID,
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(time.Hour),
	}
	if err := database.Create(&authorization).Error; err != nil {
		t.Fatalf("create OAuth authorization: %v", err)
	}
	accessToken := model.OAuthAccessToken{
		TokenID:   "access-token-id",
		ClientID:  clientID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := database.Create(&accessToken).Error; err != nil {
		t.Fatalf("create OAuth access token: %v", err)
	}
	refreshToken := model.OAuthRefreshToken{
		TokenHash: "refresh-token-hash",
		FamilyID:  "family-id",
		ClientID:  clientID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := database.Create(&refreshToken).Error; err != nil {
		t.Fatalf("create OAuth refresh token: %v", err)
	}
	auditLog := model.AuditLog{
		Action:   "test",
		Resource: "model",
		Detail:   model.JSONB(`{"test":true}`),
	}
	if err := database.Create(&auditLog).Error; err != nil {
		t.Fatalf("create audit log: %v", err)
	}

	var gotAuthorization model.OAuthAuthorization
	if err := database.First(&gotAuthorization, authorization.ID).Error; err != nil {
		t.Fatalf("read OAuth authorization: %v", err)
	}
	if gotAuthorization.RedirectURI != nil || gotAuthorization.FamilyID != nil || gotAuthorization.Nonce != nil {
		t.Fatalf("nullable OAuth authorization fields = %#v, want nil", gotAuthorization)
	}
	var gotAccessToken model.OAuthAccessToken
	if err := database.First(&gotAccessToken, accessToken.ID).Error; err != nil {
		t.Fatalf("read OAuth access token: %v", err)
	}
	if gotAccessToken.FamilyID != nil || gotAccessToken.RevokedAt != nil {
		t.Fatalf("nullable OAuth access-token fields = %#v, want nil", gotAccessToken)
	}
	var gotRefreshToken model.OAuthRefreshToken
	if err := database.First(&gotRefreshToken, refreshToken.ID).Error; err != nil {
		t.Fatalf("read OAuth refresh token: %v", err)
	}
	if gotRefreshToken.RevokedAt != nil {
		t.Fatalf("RevokedAt = %v, want nil", gotRefreshToken.RevokedAt)
	}
	var gotAuditLog model.AuditLog
	if err := database.First(&gotAuditLog, auditLog.ID).Error; err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if gotAuditLog.UserID != nil || gotAuditLog.ResourceID != nil || gotAuditLog.ClientIP != nil ||
		gotAuditLog.UserAgent != nil || gotAuditLog.ErrCode != nil {
		t.Fatalf("nullable audit-log fields = %#v, want nil", gotAuditLog)
	}
	if !jsonEqual(gotAuditLog.Detail, auditLog.Detail) {
		t.Fatalf("Detail = %s, want semantically equal JSON %s", gotAuditLog.Detail, auditLog.Detail)
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

func TestJSONBScannerAndValuer(t *testing.T) {
	var value model.JSONB
	if err := value.Scan([]byte(`{"key":"value"}`)); err != nil {
		t.Fatalf("Scan([]byte) error = %v", err)
	}
	if !reflect.DeepEqual(value, model.JSONB(`{"key":"value"}`)) {
		t.Fatalf("Scan([]byte) = %s, want original JSON", value)
	}
	stored, err := value.Value()
	if err != nil {
		t.Fatalf("Value() error = %v", err)
	}
	if !reflect.DeepEqual(stored, []byte(`{"key":"value"}`)) {
		t.Fatalf("Value() = %#v, want JSON bytes", stored)
	}
	if err := value.Scan(nil); err != nil {
		t.Fatalf("Scan(nil) error = %v", err)
	}
	if value != nil {
		t.Fatalf("Scan(nil) = %s, want nil", value)
	}
	if err := value.Scan("not bytes"); err == nil {
		t.Fatal("Scan(string) error = nil, want unsupported type error")
	}
	invalid := model.JSONB(`not-json`)
	if _, err := invalid.Value(); err == nil {
		t.Fatal("Value(invalid JSON) error = nil, want invalid JSON error")
	}
	var valuer driver.Valuer = model.JSONB(nil)
	stored, err = valuer.Value()
	if err != nil {
		t.Fatalf("Value(nil) error = %v", err)
	}
	if stored != nil {
		t.Fatalf("Value(nil) = %#v, want nil", stored)
	}
}

func TestSensitiveModelFieldsAreJSONHidden(t *testing.T) {
	passwordHash := "password-hash"
	accessToken := "third-party-access-token"
	refreshToken := "third-party-refresh-token"
	clientSecretHash := "client-secret-hash"
	authorizationCode := "authorization-code"

	testCases := []struct {
		name    string
		value   any
		secrets []string
	}{
		{
			name:    "user",
			value:   model.User{PasswordHash: passwordHash},
			secrets: []string{passwordHash},
		},
		{
			name: "identity",
			value: model.Identity{
				AccessToken:  &accessToken,
				RefreshToken: &refreshToken,
			},
			secrets: []string{accessToken, refreshToken},
		},
		{
			name:    "OAuth client",
			value:   model.OAuthClient{ClientSecretHash: &clientSecretHash},
			secrets: []string{clientSecretHash},
		},
		{
			name:    "OAuth refresh token",
			value:   model.OAuthRefreshToken{TokenHash: "refresh-token-hash"},
			secrets: []string{"refresh-token-hash"},
		},
		{
			name:    "OAuth authorization",
			value:   model.OAuthAuthorization{Code: authorizationCode},
			secrets: []string{authorizationCode},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			encoded, err := json.Marshal(testCase.value)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			for _, secret := range testCase.secrets {
				if bytes.Contains(encoded, []byte(secret)) {
					t.Fatalf("JSON %s contains secret %q", encoded, secret)
				}
			}
		})
	}
}

func migrateV1(t *testing.T, databaseURL string) {
	t.Helper()

	instance, err := migration.New(databaseURL)
	if err != nil {
		t.Fatalf("create migration: %v", err)
	}
	t.Cleanup(func() { _, _ = instance.Close() })
	if err := instance.Up(); err != nil {
		t.Fatalf("apply V001 migration: %v", err)
	}
}

func assertNilProfileFields(t *testing.T, profile model.Profile) {
	t.Helper()
	if profile.Nickname != nil || profile.Department != nil || profile.Intro != nil ||
		profile.Email != nil || profile.Avatar != nil || profile.BlogURL != nil || profile.GitHubURL != nil {
		t.Fatalf("nullable profile fields = %#v, want all nil", profile)
	}
}
