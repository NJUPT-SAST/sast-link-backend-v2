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
	if version != 4 || dirty {
		t.Fatalf("Current() = (%d, %t), want (4, false)", version, dirty)
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
		"token_blacklist_outbox",
		"v003_builtin_oauth_client_ownership",
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
	assertBuiltinOAuthClient(t, database)
}

func TestV3KeepsExistingCanonicalBuiltinOAuthClientOnDown(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	instance := newMigration(t, databaseURL)

	if err := instance.Steps(2); err != nil {
		t.Fatalf("apply V001-V002: %v", err)
	}
	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	_, err := database.ExecContext(context.Background(), `
INSERT INTO oauth_clients (
    client_id, client_name, client_type, client_secret, redirect_uris, grant_types, scopes, is_active
)
VALUES (
    'sast-link-web', 'SAST Link Web', 'first_party', NULL,
    ARRAY['https://link.sast.fun/oauth/callback', 'http://localhost:3000/oauth/callback'],
    ARRAY['authorization_code', 'refresh_token'], ARRAY['openid', 'profile', 'email'], TRUE
)
`)
	if err != nil {
		t.Fatalf("insert canonical existing built-in OAuth client: %v", err)
	}
	originalID := readOAuthClientID(t, database, "sast-link-web")

	if err := instance.Steps(2); err != nil {
		t.Fatalf("apply V003-V004: %v", err)
	}
	assertBuiltinOAuthClient(t, database)
	if err := instance.Steps(-2); err != nil {
		t.Fatalf("revert V004-V003: %v", err)
	}
	assertOAuthClientExists(t, database, "sast-link-web")
	if got := readOAuthClientID(t, database, "sast-link-web"); got != originalID {
		t.Fatalf("client ID after up/down = %d, want original %d", got, originalID)
	}
}

func TestV3RejectsNonCanonicalBuiltinOAuthClient(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	instance := newMigration(t, databaseURL)

	if err := instance.Steps(2); err != nil {
		t.Fatalf("apply V001-V002: %v", err)
	}
	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	_, err := database.ExecContext(context.Background(), `
INSERT INTO oauth_clients (
    client_id, client_name, client_type, client_secret, redirect_uris, grant_types, scopes, is_active
)
VALUES (
    'sast-link-web', 'Third-party Client', 'third_party', 'secret-hash',
    ARRAY['https://third.example/callback'], ARRAY['authorization_code'], ARRAY['openid'], TRUE
)
`)
	if err != nil {
		t.Fatalf("insert incompatible existing built-in OAuth client: %v", err)
	}

	err = instance.Up()
	if err == nil {
		t.Fatal("apply V003 with incompatible built-in OAuth client error = nil")
	}
	if !strings.Contains(err.Error(), "non-canonical sast-link-web client") {
		t.Fatalf("apply V003 error = %v, want non-canonical client blocker", err)
	}
	var clientType string
	var secret sql.NullString
	if queryErr := database.QueryRowContext(context.Background(), `
SELECT client_type::text, client_secret
FROM oauth_clients
WHERE client_id = 'sast-link-web'
`).Scan(&clientType, &secret); queryErr != nil {
		t.Fatalf("read incompatible OAuth client after failed V003: %v", queryErr)
	}
	if clientType != "third_party" || !secret.Valid || secret.String != "secret-hash" {
		t.Fatalf("client after failed V003 = (%q, %v), want original incompatible record", clientType, secret)
	}
}

func TestV3DownKeepsReferencedBuiltinOAuthClient(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	instance := newMigration(t, databaseURL)

	if err := instance.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	userID := insertTestUser(t, database)
	builtinClientID := readOAuthClientID(t, database, "sast-link-web")
	insertOAuthAuthorization(t, database, "v3-down-referenced-code", builtinClientID, userID, "S256")

	if err := instance.Steps(-2); err != nil {
		t.Fatalf("Steps(-2) error = %v", err)
	}
	version, dirty, err := migration.Current(databaseURL)
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if version != 2 || dirty {
		t.Fatalf("Current() = (%d, %t), want (2, false)", version, dirty)
	}
	assertOAuthClientExists(t, database, "sast-link-web")
}

func TestV3DownKeepsMutatedBuiltinOAuthClient(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	instance := newMigration(t, databaseURL)

	if err := instance.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	_, err := database.ExecContext(context.Background(), `
UPDATE oauth_clients
SET client_name = 'Hijacked Client',
    client_type = 'third_party',
    client_secret = 'secret-hash',
    redirect_uris = ARRAY['https://evil.example/callback'],
    grant_types = ARRAY['authorization_code'],
    scopes = ARRAY['email', 'openid'],
    is_active = FALSE
WHERE client_id = 'sast-link-web'
`)
	if err != nil {
		t.Fatalf("mutate built-in OAuth client before V003 down: %v", err)
	}

	if err := instance.Steps(-2); err != nil {
		t.Fatalf("Steps(-2) error = %v", err)
	}
	assertOAuthClientExists(t, database, "sast-link-web")
}

func TestV3DownDeletesUnreferencedBuiltinOAuthClient(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	instance := newMigration(t, databaseURL)

	if err := instance.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })

	if err := instance.Steps(-2); err != nil {
		t.Fatalf("Steps(-2) error = %v", err)
	}
	assertOAuthClientMissing(t, database, "sast-link-web")
}

func TestV2DownRestoresV1PKCEChallengeMethodConstraint(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	instance := newMigration(t, databaseURL)

	if err := instance.Steps(2); err != nil {
		t.Fatalf("apply V001-V002: %v", err)
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
	var constraintDefinition string
	if queryErr := database.QueryRowContext(context.Background(), `
SELECT pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conrelid = 'oauth_authorizations'::regclass
  AND conname = 'ck_oauth_authorizations_challenge_method'
`).Scan(&constraintDefinition); queryErr != nil {
		t.Fatalf("read challenge-method constraint after failed V002: %v", queryErr)
	}
	if !strings.Contains(constraintDefinition, "plain") {
		t.Fatalf("constraint after failed V002 = %q, want original V001 plain allowance", constraintDefinition)
	}
}

func TestBaselineV1CanMigrateToLatest(t *testing.T) {
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
		t.Fatalf("Current() after latest migrations error = %v", err)
	}
	if version != 4 || dirty {
		t.Fatalf("Current() after latest migrations = (%d, %t), want (4, false)", version, dirty)
	}

	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	userID := insertTestUser(t, database)
	assertRejectsPlainPKCEChallengeMethod(t, database, userID)
	assertBuiltinOAuthClient(t, database)
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

func assertBuiltinOAuthClient(t *testing.T, database *sql.DB) {
	t.Helper()

	var name, clientType string
	var secretIsNull, active bool
	var redirectURIs, grantTypes, scopes string
	err := database.QueryRowContext(context.Background(), `
SELECT client_name,
       client_type::text,
       client_secret IS NULL,
       array_to_string(redirect_uris, E'\n'),
       array_to_string(grant_types, E'\n'),
       array_to_string(scopes, E'\n'),
       is_active
FROM oauth_clients
WHERE client_id = 'sast-link-web'
`).Scan(&name, &clientType, &secretIsNull, &redirectURIs, &grantTypes, &scopes, &active)
	if err != nil {
		t.Fatalf("read built-in OAuth client: %v", err)
	}
	if name != "SAST Link Web" || clientType != "first_party" || !secretIsNull ||
		redirectURIs != "https://link.sast.fun/oauth/callback\nhttp://localhost:3000/oauth/callback" ||
		grantTypes != "authorization_code\nrefresh_token" || scopes != "openid\nprofile\nemail" || !active {
		t.Fatalf(
			"built-in OAuth client = (%q, %q, secret null %t, %q, %q, %q, active %t), want canonical sast-link-web",
			name,
			clientType,
			secretIsNull,
			redirectURIs,
			grantTypes,
			scopes,
			active,
		)
	}
}

func readOAuthClientID(t *testing.T, database *sql.DB, clientIDValue string) int64 {
	t.Helper()

	var clientID int64
	if err := database.QueryRowContext(context.Background(), `
SELECT id FROM oauth_clients WHERE client_id = $1
`, clientIDValue).Scan(&clientID); err != nil {
		t.Fatalf("read OAuth client %q ID: %v", clientIDValue, err)
	}
	return clientID
}

func assertOAuthClientExists(t *testing.T, database *sql.DB, clientIDValue string) {
	t.Helper()

	var exists bool
	if err := database.QueryRowContext(context.Background(), `
SELECT EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = $1)
`, clientIDValue).Scan(&exists); err != nil {
		t.Fatalf("query OAuth client %q existence: %v", clientIDValue, err)
	}
	if !exists {
		t.Fatalf("OAuth client %q is missing", clientIDValue)
	}
}

func assertOAuthClientMissing(t *testing.T, database *sql.DB, clientIDValue string) {
	t.Helper()

	var exists bool
	if err := database.QueryRowContext(context.Background(), `
SELECT EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = $1)
`, clientIDValue).Scan(&exists); err != nil {
		t.Fatalf("query OAuth client %q absence: %v", clientIDValue, err)
	}
	if exists {
		t.Fatalf("OAuth client %q remains", clientIDValue)
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
