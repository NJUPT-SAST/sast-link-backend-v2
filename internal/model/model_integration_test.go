package model_test

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/migration"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
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
		StudentID:    "B24040001",
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
	if gotUser.StudentID != "B24040001" {
		t.Fatalf("StudentID = %q, want B24040001", gotUser.StudentID)
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
	if client.IsActive == nil || !*client.IsActive || gotClient.IsActive == nil || !*gotClient.IsActive {
		t.Fatalf("IsActive after default = %v/%v, want true/true", client.IsActive, gotClient.IsActive)
	}
	assertBooleanDefaults(t, database, user.ID)
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

func TestModelCreateUsesPersistenceDefaultsAndPreservesExplicitValues(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	migrateV1(t, databaseURL)
	database := testutil.OpenGORM(t, databaseURL)

	defaultUser := model.User{
		Name:         "Default User",
		PhoneNumber:  "13800138001",
		QQNumber:     "10001",
		PasswordHash: "password-hash",
		StudentID:    "B24040002",
		LoginEmail:   "default@sast.fun",
	}
	if err := database.Create(&defaultUser).Error; err != nil {
		t.Fatalf("create user with defaults: %v", err)
	}
	if defaultUser.Role != model.UserRoleFreshman || defaultUser.State != model.UserStateNJUPTer ||
		defaultUser.College != model.CollegeOther || defaultUser.EmailType != model.EmailTypeSAST {
		t.Fatalf("default user = %#v, want DB defaults and trigger-derived email type", defaultUser)
	}

	explicitUser := model.User{
		Role:         model.UserRoleAdmin,
		Name:         "Explicit User",
		PhoneNumber:  "13800138002",
		QQNumber:     "10002",
		PasswordHash: "password-hash",
		StudentID:    "B24040003",
		State:        model.UserStateOnSAST,
		EmailType:    model.EmailTypeSAST,
		LoginEmail:   "explicit@njupt.edu.cn",
		College:      model.CollegeComputerSoftwareCybersecurity,
	}
	if err := database.Create(&explicitUser).Error; err != nil {
		t.Fatalf("create user with explicit values: %v", err)
	}
	if explicitUser.Role != model.UserRoleAdmin || explicitUser.State != model.UserStateOnSAST ||
		explicitUser.College != model.CollegeComputerSoftwareCybersecurity || explicitUser.EmailType != model.EmailTypeNJUpt {
		t.Fatalf("explicit user = %#v, want role/state/college preserved and email type trigger-derived", explicitUser)
	}

	defaultClient := model.OAuthClient{
		ClientID:     "default-scopes-client",
		ClientName:   "Default Scopes Client",
		ClientType:   model.ClientTypeFirstParty,
		RedirectURIs: model.StringArray{"https://example.test/default"},
		GrantTypes:   model.StringArray{"authorization_code"},
	}
	if err := database.Create(&defaultClient).Error; err != nil {
		t.Fatalf("create OAuth client with default scopes: %v", err)
	}
	if defaultClient.Scopes == nil || len(defaultClient.Scopes) != 0 {
		t.Fatalf("default Scopes = %#v, want non-nil empty array", defaultClient.Scopes)
	}

	explicitScopes := model.StringArray{"openid", "profile"}
	explicitClient := model.OAuthClient{
		ClientID:     "explicit-scopes-client",
		ClientName:   "Explicit Scopes Client",
		ClientType:   model.ClientTypeFirstParty,
		RedirectURIs: model.StringArray{"https://example.test/explicit"},
		GrantTypes:   model.StringArray{"authorization_code"},
		Scopes:       explicitScopes,
	}
	if err := database.Create(&explicitClient).Error; err != nil {
		t.Fatalf("create OAuth client with explicit scopes: %v", err)
	}
	if !reflect.DeepEqual(explicitClient.Scopes, explicitScopes) {
		t.Fatalf("explicit Scopes = %#v, want %#v", explicitClient.Scopes, explicitScopes)
	}

	defaultAudit := model.AuditLog{Action: "default-detail", Resource: "model"}
	if err := database.Create(&defaultAudit).Error; err != nil {
		t.Fatalf("create audit log with default detail: %v", err)
	}
	if !jsonEqual(defaultAudit.Detail, model.JSONB(`{}`)) {
		t.Fatalf("default Detail = %s, want empty JSON object", defaultAudit.Detail)
	}
	explicitDetail := model.JSONB(`{"source":"explicit"}`)
	explicitAudit := model.AuditLog{Action: "explicit-detail", Resource: "model", Detail: explicitDetail}
	if err := database.Create(&explicitAudit).Error; err != nil {
		t.Fatalf("create audit log with explicit detail: %v", err)
	}
	if !jsonEqual(explicitAudit.Detail, explicitDetail) {
		t.Fatalf("explicit Detail = %s, want %s", explicitAudit.Detail, explicitDetail)
	}
}

func TestStringArrayValueRejectsNUL(t *testing.T) {
	var valuer driver.Valuer = model.StringArray{"valid", "contains\x00nul"}
	value, err := valuer.Value()
	if err == nil {
		t.Fatalf("Value() = %#v, nil; want NUL error", value)
	}
	if value != nil {
		t.Fatalf("Value() = %#v, want nil on error", value)
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

func assertBooleanDefaults(t *testing.T, database *gorm.DB, userID int64) {
	t.Helper()

	falseValue := false
	trueValue := true
	client := model.OAuthClient{
		ClientID:     "explicit-inactive-client",
		ClientName:   "Explicit Inactive Client",
		ClientType:   model.ClientTypeFirstParty,
		RedirectURIs: model.StringArray{"https://example.test/inactive"},
		GrantTypes:   model.StringArray{"authorization_code"},
		Scopes:       model.StringArray{},
		IsActive:     &falseValue,
	}
	if err := database.Create(&client).Error; err != nil {
		t.Fatalf("create explicitly inactive OAuth client: %v", err)
	}
	var gotClient model.OAuthClient
	if err := database.First(&gotClient, client.ID).Error; err != nil {
		t.Fatalf("read explicitly inactive OAuth client: %v", err)
	}
	if gotClient.IsActive == nil || *gotClient.IsActive {
		t.Fatalf("explicit IsActive = %v, want false", gotClient.IsActive)
	}

	activeClient := model.OAuthClient{
		ClientID:     "explicit-active-client",
		ClientName:   "Explicit Active Client",
		ClientType:   model.ClientTypeFirstParty,
		RedirectURIs: model.StringArray{"https://example.test/active"},
		GrantTypes:   model.StringArray{"authorization_code"},
		Scopes:       model.StringArray{},
		IsActive:     &trueValue,
	}
	if err := database.Create(&activeClient).Error; err != nil {
		t.Fatalf("create explicitly active OAuth client: %v", err)
	}
	if activeClient.IsActive == nil || !*activeClient.IsActive {
		t.Fatalf("explicit IsActive = %v, want true", activeClient.IsActive)
	}

	defaultAudit := model.AuditLog{Action: "default", Resource: "model"}
	if err := database.Create(&defaultAudit).Error; err != nil {
		t.Fatalf("create default-success audit log: %v", err)
	}
	if defaultAudit.Success == nil || !*defaultAudit.Success {
		t.Fatalf("Success after default = %v, want true", defaultAudit.Success)
	}

	failedAudit := model.AuditLog{
		UserID:   &userID,
		Action:   "failed",
		Resource: "model",
		Success:  &falseValue,
	}
	if err := database.Create(&failedAudit).Error; err != nil {
		t.Fatalf("create failed audit log: %v", err)
	}
	var gotFailedAudit model.AuditLog
	if err := database.First(&gotFailedAudit, failedAudit.ID).Error; err != nil {
		t.Fatalf("read failed audit log: %v", err)
	}
	if gotFailedAudit.Success == nil || *gotFailedAudit.Success {
		t.Fatalf("explicit Success = %v, want false", gotFailedAudit.Success)
	}

	successfulAudit := model.AuditLog{
		Action:   "successful",
		Resource: "model",
		Success:  &trueValue,
	}
	if err := database.Create(&successfulAudit).Error; err != nil {
		t.Fatalf("create explicitly successful audit log: %v", err)
	}
	if successfulAudit.Success == nil || !*successfulAudit.Success {
		t.Fatalf("explicit Success = %v, want true", successfulAudit.Success)
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
	if auditLog.Success == nil || !*auditLog.Success || gotAuditLog.Success == nil || !*gotAuditLog.Success {
		t.Fatalf("Success after default = %v/%v, want true/true", auditLog.Success, gotAuditLog.Success)
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
	scanErr := value.Scan(nil)
	if scanErr != nil {
		t.Fatalf("Scan(nil) error = %v", scanErr)
	}
	if value != nil {
		t.Fatalf("Scan(nil) = %s, want nil", value)
	}
	scanErr = value.Scan("not bytes")
	if scanErr == nil {
		t.Fatal("Scan(string) error = nil, want unsupported type error")
	}
	invalid := model.JSONB(`not-json`)
	_, invalidErr := invalid.Value()
	if invalidErr == nil {
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
	accessToken := "third-party-access-token"   //nolint:gosec // Non-secret fixture used to verify JSON redaction.
	refreshToken := "third-party-refresh-token" //nolint:gosec // Non-secret fixture used to verify JSON redaction.
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
