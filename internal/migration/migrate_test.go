package migration_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/migration"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
)

const tableExistsQuery = `SELECT to_regclass('public.' || $1) IS NOT NULL`

const enumExistsQuery = `SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_type typ
  JOIN pg_catalog.pg_namespace ns ON ns.oid = typ.typnamespace
  WHERE ns.nspname = 'public' AND typ.typname = $1
)`

const triggerExistsQuery = `SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_trigger
  WHERE tgname = $1 AND NOT tgisinternal
)`

func TestNewRejectsMissingDatabaseName(t *testing.T) {
	for _, databaseURL := range []string{
		"postgres://user:password@localhost",
		"postgres://user:password@localhost/",
	} {
		t.Run(databaseURL, func(t *testing.T) {
			instance, err := migration.New(databaseURL)
			if instance != nil {
				_, _ = instance.Close()
				t.Fatal("New() instance is non-nil, want nil")
			}
			if err == nil {
				t.Fatal("New() error = nil, want missing database name error")
			}
			if !strings.Contains(err.Error(), "database name") {
				t.Fatalf("New() error = %v, want missing database name error", err)
			}
		})
	}
}

func TestUpCreatesLatestSchema(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	instance := newMigration(t, databaseURL)

	if err := instance.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}

	version, dirty, err := migration.Current(databaseURL)
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if version != 2 || dirty {
		t.Fatalf("Current() = (%d, %t), want (2, false)", version, dirty)
	}

	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })

	for _, tableName := range []string{
		"user",
		"oauth_clients",
		"profile",
		"identities",
		"oauth_authorizations",
		"oauth_access_tokens",
		"oauth_refresh_tokens",
		"audit_logs",
	} {
		assertExists(t, database, tableExistsQuery, tableName)
	}

	for _, enumName := range []string{
		"user_role_enum",
		"department_enum",
		"login_method_enum",
		"state_enum",
		"email_enum",
		"client_enum",
		"college_enum",
	} {
		assertExists(t, database, enumExistsQuery, enumName)
	}

	for _, triggerName := range []string{
		"trg_user_email_domain",
		"trg_identities_other_mail_limit",
	} {
		assertExists(t, database, triggerExistsQuery, triggerName)
	}

	userID := insertTestUser(t, database)
	assertRejectsInvalidEmailDomain(t, database)
	assertOtherMailLimit(t, database, userID)
	assertRefreshTokenFamilySequenceUnique(t, database, userID)
	assertRejectsPlainPKCEChallengeMethod(t, database, userID)
}

func TestV2DownRestoresV1PKCEChallengeMethodConstraint(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	instance := newMigration(t, databaseURL)

	if err := instance.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if err := instance.Steps(-1); err != nil {
		t.Fatalf("Steps(-1) error = %v", err)
	}

	version, dirty, err := migration.Current(databaseURL)
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if version != 1 || dirty {
		t.Fatalf("Current() = (%d, %t), want (1, false)", version, dirty)
	}

	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	userID := insertTestUser(t, database)
	clientID := insertTestOAuthClient(t, database, "v2-down-client")
	insertOAuthAuthorization(t, database, "v2-down-plain", clientID, userID, "plain")
}

func TestV2RejectsExistingPlainPKCEChallengeMethod(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	instance := newMigration(t, databaseURL)

	if err := instance.Steps(1); err != nil {
		t.Fatalf("apply V001: %v", err)
	}
	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	userID := insertTestUser(t, database)
	clientID := insertTestOAuthClient(t, database, "v2-block-client")
	insertOAuthAuthorization(t, database, "v2-block-plain", clientID, userID, "plain")

	err := instance.Up()
	if err == nil {
		t.Fatal("Up() with existing plain PKCE challenge method error = nil")
	}
	if !strings.Contains(err.Error(), "non-S256 code_challenge_method") {
		t.Fatalf("Up() error = %v, want non-S256 blocker", err)
	}
}

func TestBaselineV1CanMigrateToV2(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	applyUnversionedV1Schema(t, databaseURL)

	if err := migration.BaselineV1(context.Background(), databaseURL); err != nil {
		t.Fatalf("BaselineV1() error = %v", err)
	}
	version, dirty, err := migration.Current(databaseURL)
	if err != nil {
		t.Fatalf("Current() after baseline error = %v", err)
	}
	if version != 1 || dirty {
		t.Fatalf("Current() after baseline = (%d, %t), want (1, false)", version, dirty)
	}

	instance := newMigration(t, databaseURL)
	migrateErr := instance.Up()
	if migrateErr != nil {
		t.Fatalf("Up() after baseline error = %v", migrateErr)
	}
	version, dirty, err = migration.Current(databaseURL)
	if err != nil {
		t.Fatalf("Current() after V002 error = %v", err)
	}
	if version != 2 || dirty {
		t.Fatalf("Current() after V002 = (%d, %t), want (2, false)", version, dirty)
	}

	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	userID := insertTestUser(t, database)
	assertRejectsPlainPKCEChallengeMethod(t, database, userID)
}

func TestDownDropsV1Schema(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	instance := newMigration(t, databaseURL)

	if err := instance.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if err := instance.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}

	version, dirty, err := migration.Current(databaseURL)
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if version != 0 || dirty {
		t.Fatalf("Current() = (%d, %t), want (0, false)", version, dirty)
	}

	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })

	var table sql.NullString
	if err := database.QueryRowContext(context.Background(), `SELECT to_regclass('public.user')`).Scan(&table); err != nil {
		t.Fatalf("query user table: %v", err)
	}
	if table.Valid {
		t.Fatalf("user table remains after Down(): %q", table.String)
	}
}

func newMigration(t *testing.T, databaseURL string) *migrate.Migrate {
	t.Helper()

	instance, err := migration.New(databaseURL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _, _ = instance.Close() })
	return instance
}

func assertExists(t *testing.T, database *sql.DB, query string, name string) {
	t.Helper()

	var exists bool
	if err := database.QueryRowContext(context.Background(), query, name).Scan(&exists); err != nil {
		t.Fatalf("query existence for %q: %v", name, err)
	}
	if !exists {
		t.Fatalf("required object %q is missing", name)
	}
}

func insertTestUser(t *testing.T, database *sql.DB) int64 {
	t.Helper()

	var userID int64
	var emailType string
	err := database.QueryRowContext(context.Background(), `
INSERT INTO "user" (name, phone_number, qq_number, password, login_email, student_id, college, major)
VALUES ('Test User', '13800138000', '10000', 'hash', 'user@njupt.edu.cn', 'B24040001', '其他', '')
RETURNING id, email_type
`).Scan(&userID, &emailType)
	if err != nil {
		t.Fatalf("insert user with NJUPT email: %v", err)
	}
	if emailType != "njupt_email" {
		t.Fatalf("email_type = %q, want %q", emailType, "njupt_email")
	}
	return userID
}

func insertTestOAuthClient(t *testing.T, database *sql.DB, clientIDValue string) int64 {
	t.Helper()

	var clientID int64
	err := database.QueryRowContext(context.Background(), `
	INSERT INTO oauth_clients (client_id, client_name, client_type, redirect_uris, grant_types)
	VALUES ($1, 'Test Client', 'first_party', ARRAY['https://example.com/callback'], ARRAY['authorization_code'])
	RETURNING id
	`, clientIDValue).Scan(&clientID)
	if err != nil {
		t.Fatalf("insert OAuth client %q: %v", clientIDValue, err)
	}
	return clientID
}

func insertOAuthAuthorization(
	t *testing.T,
	database *sql.DB,
	code string,
	clientID int64,
	userID int64,
	challengeMethod string,
) {
	t.Helper()

	_, err := database.ExecContext(context.Background(), `
	INSERT INTO oauth_authorizations (
	    code, client_id, user_id, scopes, code_challenge, code_challenge_method, expires_at
	)
	VALUES ($1, $2, $3, ARRAY['openid'], 'challenge', $4, NOW() + INTERVAL '10 minutes')
	`, code, clientID, userID, challengeMethod)
	if err != nil {
		t.Fatalf("insert OAuth authorization %q with %q challenge method: %v", code, challengeMethod, err)
	}
}

func assertRejectsPlainPKCEChallengeMethod(t *testing.T, database *sql.DB, userID int64) {
	t.Helper()

	clientID := insertTestOAuthClient(t, database, "pkce-s256-client")
	insertOAuthAuthorization(t, database, "pkce-s256-code", clientID, userID, "S256")
	_, err := database.ExecContext(context.Background(), `
	INSERT INTO oauth_authorizations (
	    code, client_id, user_id, scopes, code_challenge, code_challenge_method, expires_at
	)
	VALUES ('pkce-plain-code', $1, $2, ARRAY['openid'], 'challenge', 'plain', NOW() + INTERVAL '10 minutes')
	`, clientID, userID)
	if err == nil {
		t.Fatal("insert OAuth authorization with plain PKCE challenge method succeeded")
	}
}

func assertRejectsInvalidEmailDomain(t *testing.T, database *sql.DB) {
	t.Helper()

	_, err := database.ExecContext(context.Background(), `
INSERT INTO "user" (name, phone_number, qq_number, password, login_email, student_id, college, major)
VALUES ('Bad User', '13800138001', '10001', 'hash', 'user@example.com', 'B24040002', '其他', '')
`)
	if err == nil {
		t.Fatal("insert user with invalid email domain succeeded")
	}
}

func assertOtherMailLimit(t *testing.T, database *sql.DB, userID int64) {
	t.Helper()

	for _, providerID := range []string{"first@example.com", "second@example.com"} {
		if _, err := database.ExecContext(context.Background(),
			`INSERT INTO identities (user_id, provider, provider_id) VALUES ($1, 'other_mail', $2)`,
			userID,
			providerID,
		); err != nil {
			t.Fatalf("insert other_mail identity %q: %v", providerID, err)
		}
	}

	_, err := database.ExecContext(context.Background(),
		`INSERT INTO identities (user_id, provider, provider_id) VALUES ($1, 'other_mail', $2)`,
		userID,
		"third@example.com",
	)
	if err == nil {
		t.Fatal("third other_mail identity insert succeeded")
	}
}

func assertRefreshTokenFamilySequenceUnique(t *testing.T, database *sql.DB, userID int64) {
	t.Helper()

	var clientID int64
	err := database.QueryRowContext(context.Background(), `
INSERT INTO oauth_clients (client_id, client_name, client_type, redirect_uris, grant_types)
VALUES (
    'test-client',
    'Test Client',
    'first_party',
    ARRAY['https://example.com/callback'],
    ARRAY['authorization_code']
)
RETURNING id
`).Scan(&clientID)
	if err != nil {
		t.Fatalf("insert OAuth client: %v", err)
	}

	_, insertErr := database.ExecContext(context.Background(), `
INSERT INTO oauth_refresh_tokens (token_hash, family_id, sequence, client_id, user_id, expires_at)
VALUES ('token-hash-one', 'family-one', 0, $1, $2, NOW() + INTERVAL '1 hour')
`, clientID, userID)
	if insertErr != nil {
		t.Fatalf("insert first refresh token: %v", insertErr)
	}

	_, err = database.ExecContext(context.Background(), `
INSERT INTO oauth_refresh_tokens (token_hash, family_id, sequence, client_id, user_id, expires_at)
VALUES ('token-hash-two', 'family-one', 0, $1, $2, NOW() + INTERVAL '1 hour')
`, clientID, userID)
	if err == nil {
		t.Fatal("duplicate refresh token family sequence insert succeeded")
	}
}
