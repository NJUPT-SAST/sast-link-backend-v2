package migration_test

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"

	migrations "github.com/NJUPT-SAST/sast-link-backend-v2/migrations"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/migration"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
)

// latestMigrationVersion is derived from the embedded migration set rather than
// hardcoded, so adding a migration does not require editing assertions that are
// really about "Up() reaches the newest version".
var latestMigrationVersion = highestMigrationVersion()

func highestMigrationVersion() uint {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		panic("read embedded migrations: " + err.Error())
	}
	var highest uint64
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		version, parseErr := strconv.ParseUint(strings.SplitN(name, "_", 2)[0], 10, 64)
		if parseErr != nil {
			continue
		}
		if version > highest {
			highest = version
		}
	}
	return uint(highest)
}

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

const indexExistsQuery = `SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_indexes
  WHERE schemaname = 'public' AND indexname = $1
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
	if version != latestMigrationVersion || dirty {
		t.Fatalf("Current() = (%d, %t), want (%d, false)", version, dirty, latestMigrationVersion)
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
		"trg_identities_provider_id_not_login_email",
		"trg_user_login_email_not_identity",
	} {
		assertExists(t, database, triggerExistsQuery, triggerName)
	}

	// V006. The retention worker sweeps expired authorization codes regardless of
	// is_used, which V001's partial index (WHERE is_used = FALSE) cannot serve —
	// redeemed codes are the common case, so without this the hourly sweep is a
	// sequential scan over the whole table.
	assertExists(t, database, indexExistsQuery, "idx_oauth_authorizations_expires_at_all")

	userID := insertTestUser(t, database)
	assertRejectsInvalidEmailDomain(t, database)
	assertOtherMailLimit(t, database, userID)
	assertRefreshTokenFamilySequenceUnique(t, database, userID)
	assertRejectsPlainPKCEChallengeMethod(t, database, userID)
	assertBuiltinOAuthClient(t, database)
}

func TestV5RejectsExistingCrossTableEmailConflict(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	instance := newMigration(t, databaseURL)
	if err := instance.Steps(4); err != nil {
		t.Fatalf("apply V001-V004: %v", err)
	}
	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	userID := insertTestUser(t, database)
	if _, err := database.ExecContext(context.Background(), `
INSERT INTO identities (user_id, provider, provider_id)
VALUES ($1, 'other_mail', 'user@njupt.edu.cn')`, userID); err != nil {
		t.Fatalf("insert existing cross-table conflict: %v", err)
	}

	err := instance.Up()
	if err == nil || !strings.Contains(err.Error(), "existing conflicts found") {
		t.Fatalf("apply V005 error = %v, want existing conflict blocker", err)
	}
	var identityCount int
	if queryErr := database.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM identities WHERE provider_id = 'user@njupt.edu.cn'`).Scan(&identityCount); queryErr != nil {
		t.Fatalf("count preserved identity: %v", queryErr)
	}
	if identityCount != 1 {
		t.Fatalf("identity count = %d, want conflict preserved for manual repair", identityCount)
	}
	var triggerExists bool
	if queryErr := database.QueryRowContext(context.Background(), triggerExistsQuery, "trg_user_login_email_not_identity").Scan(&triggerExists); queryErr != nil {
		t.Fatalf("query V005 trigger: %v", queryErr)
	}
	if triggerExists {
		t.Fatal("V005 trigger installed despite failed preflight")
	}
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

// seededClient is one row of V008's seed, with the array columns joined in SQL: lib/pq
// is not a dependency of this module, and a comma-joined string asserts both membership
// and order.
type seededClient struct {
	clientType   string
	secret       sql.NullString
	redirectURIs string
	grantTypes   string
	scopes       string
	isActive     bool
}

func readSeededClient(t *testing.T, database *sql.DB, clientID string) seededClient {
	t.Helper()
	var got seededClient
	if err := database.QueryRowContext(context.Background(), `
SELECT client_type::text,
       client_secret,
       array_to_string(redirect_uris, ','),
       array_to_string(grant_types, ','),
       array_to_string(scopes, ','),
       is_active
FROM oauth_clients
WHERE client_id = $1
`, clientID).Scan(&got.clientType, &got.secret, &got.redirectURIs,
		&got.grantTypes, &got.scopes, &got.isActive); err != nil {
		t.Fatalf("read seeded %s client: %v", clientID, err)
	}
	return got
}

// V008's two clients are asserted property by property rather than trusted to the seed:
// a drifted seed still applies cleanly, and each of these properties is load-bearing.
//
// The split itself is the point. The admin client must not be refreshable — the refresh
// flow inherits scopes without narrowing, so a refreshable admin:write token renews
// itself indefinitely — while the session client must be, since keeping a sign-in alive
// is its whole job and it holds nothing administrative. Both must be third_party, which
// is what subjects them to the registered-scope check at all.
func TestV8SeedsDelegatedAdminAndSessionClients(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	instance := newMigration(t, databaseURL)
	if err := instance.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })

	const wantRedirects = "https://people.sast.fun/api/auth/link,http://localhost:3001/api/auth/link"

	admin := readSeededClient(t, database, "sast-people-admin")
	if admin.clientType != "third_party" {
		t.Fatalf("admin client_type = %q, want third_party; a first_party client is public and may not hold admin scope", admin.clientType)
	}
	if !admin.secret.Valid || !strings.HasPrefix(admin.secret.String, "sha256-v1$") {
		t.Fatalf("admin client_secret = %v, want a sha256-v1 hash", admin.secret)
	}
	if strings.Contains(admin.grantTypes, "refresh_token") {
		t.Fatalf("admin grant_types = %q, want no refresh_token: the refresh grant does not narrow scopes", admin.grantTypes)
	}
	if admin.grantTypes != "authorization_code" {
		t.Fatalf("admin grant_types = %q, want authorization_code alone", admin.grantTypes)
	}
	if admin.scopes != "openid,admin:read,admin:write" {
		t.Fatalf("admin scopes = %q, want openid plus both admin scopes", admin.scopes)
	}
	if admin.redirectURIs != wantRedirects {
		t.Fatalf("admin redirect_uris = %q, want the registered callbacks", admin.redirectURIs)
	}
	if !admin.isActive {
		t.Fatal("admin is_active = false, want the seeded client enabled")
	}

	session := readSeededClient(t, database, "sast-people-session")
	if session.clientType != "third_party" {
		t.Fatalf("session client_type = %q, want third_party", session.clientType)
	}
	if !session.secret.Valid || !strings.HasPrefix(session.secret.String, "sha256-v1$") {
		t.Fatalf("session client_secret = %v, want a sha256-v1 hash", session.secret)
	}
	if session.secret.String == admin.secret.String {
		t.Fatal("both clients share one secret hash; a leak of either would compromise both")
	}
	if session.grantTypes != "authorization_code,refresh_token" {
		t.Fatalf("session grant_types = %q, want authorization_code plus refresh_token", session.grantTypes)
	}
	// The session credential must hold nothing administrative: that is what makes it
	// safe to refresh indefinitely.
	if strings.Contains(session.scopes, "admin:") {
		t.Fatalf("session scopes = %q, want no admin scope on a refreshable client", session.scopes)
	}
	if session.scopes != "openid,profile,email" {
		t.Fatalf("session scopes = %q, want the three OIDC scopes", session.scopes)
	}
	if session.redirectURIs != wantRedirects {
		t.Fatalf("session redirect_uris = %q, want the registered callbacks", session.redirectURIs)
	}
	if !session.isActive {
		t.Fatal("session is_active = false, want the seeded client enabled")
	}
}

// Re-applying over an existing but different row must abort rather than overwrite:
// silently rewriting could widen the scopes or repoint the callbacks of a live client.
// Both seeded ids are checked, since the migration inserts them in sequence and a guard
// present on only the first would leave the second overwritable.
func TestV8RejectsNonCanonicalSeededClients(t *testing.T) {
	for _, clientID := range []string{"sast-people-admin", "sast-people-session"} {
		t.Run(clientID, func(t *testing.T) {
			databaseURL := testutil.StartPostgres(t)
			instance := newMigration(t, databaseURL)
			if err := instance.Steps(7); err != nil {
				t.Fatalf("apply V001-V007: %v", err)
			}
			database := testutil.OpenSQL(t, databaseURL)
			t.Cleanup(func() { _ = database.Close() })
			if _, err := database.ExecContext(context.Background(), `
INSERT INTO oauth_clients (
    client_id, client_name, client_type, client_secret, redirect_uris, grant_types, scopes, is_active
)
VALUES (
    $1, 'Impostor', 'third_party', 'sha256-v1$whatever',
    ARRAY['https://attacker.test/cb'], ARRAY['authorization_code'],
    ARRAY['openid', 'admin:write'], TRUE
)
`, clientID); err != nil {
				t.Fatalf("insert conflicting %s client: %v", clientID, err)
			}

			err := instance.Up()
			if err == nil {
				t.Fatalf("apply V008 over a conflicting %s client error = nil", clientID)
			}
			if !strings.Contains(err.Error(), "non-canonical "+clientID+" client") {
				t.Fatalf("apply V008 error = %v, want the non-canonical %s blocker", err, clientID)
			}
			var redirectURIs string
			if queryErr := database.QueryRowContext(context.Background(), `
SELECT array_to_string(redirect_uris, ',') FROM oauth_clients WHERE client_id = $1
`, clientID).Scan(&redirectURIs); queryErr != nil {
				t.Fatalf("read %s client after failed V008: %v", clientID, queryErr)
			}
			if redirectURIs != "https://attacker.test/cb" {
				t.Fatalf("redirect_uris after failed V008 = %q, want the row left untouched", redirectURIs)
			}
		})
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

	if err := instance.Migrate(2); err != nil {
		t.Fatalf("Migrate(2) error = %v", err)
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

	if err := instance.Migrate(2); err != nil {
		t.Fatalf("Migrate(2) error = %v", err)
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

	if err := instance.Migrate(2); err != nil {
		t.Fatalf("Migrate(2) error = %v", err)
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
	if version != latestMigrationVersion || dirty {
		t.Fatalf("Current() after latest migrations = (%d, %t), want (%d, false)", version, dirty, latestMigrationVersion)
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
