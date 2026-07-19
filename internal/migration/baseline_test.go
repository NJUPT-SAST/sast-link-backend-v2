package migration_test

import (
	"context"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/migration"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
)

func applyV1(t *testing.T, databaseURL string) {
	t.Helper()

	instance, err := migration.New(databaseURL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _, _ = instance.Close() })
	if err := instance.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
}

func applyUnversionedV1Schema(t *testing.T, databaseURL string) {
	t.Helper()

	instance, err := migration.New(databaseURL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := instance.Up(); err != nil {
		_, _ = instance.Close()
		t.Fatalf("Up() error = %v", err)
	}
	if _, err := instance.Close(); err != nil {
		t.Fatalf("close migration instance: %v", err)
	}

	database := testutil.OpenSQL(t, databaseURL)
	defer func() { _ = database.Close() }()
	if _, err := database.ExecContext(context.Background(), `DROP TABLE schema_migrations`); err != nil {
		t.Fatalf("drop migration table to simulate existing schema: %v", err)
	}
}

func TestBaselineV1RejectsEmptyDatabase(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)

	err := migration.BaselineV1(context.Background(), databaseURL)
	if err == nil {
		t.Fatal("BaselineV1() error = nil, want empty database rejection")
	}
	if !strings.Contains(err.Error(), `missing required table "user"`) {
		t.Fatalf("BaselineV1() error = %v, want missing user table", err)
	}
}

func TestBaselineV1RejectsWrongVersion(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	applyV1(t, databaseURL)

	instance, err := migration.New(databaseURL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _, _ = instance.Close() })
	forceErr := instance.Force(2)
	if forceErr != nil {
		t.Fatalf("Force(2) error = %v", forceErr)
	}

	err = migration.BaselineV1(context.Background(), databaseURL)
	if err == nil {
		t.Fatal("BaselineV1() error = nil, want wrong-version rejection")
	}
	if !strings.Contains(err.Error(), "version 2") {
		t.Fatalf("BaselineV1() error = %v, want version 2 rejection", err)
	}
}

func TestBaselineV1RejectsDirtyVersionOne(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	applyV1(t, databaseURL)

	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.ExecContext(context.Background(), `UPDATE schema_migrations SET dirty = true`); err != nil {
		t.Fatalf("mark migration dirty: %v", err)
	}

	err := migration.BaselineV1(context.Background(), databaseURL)
	if err == nil {
		t.Fatal("BaselineV1() error = nil, want dirty-state rejection")
	}
	if !strings.Contains(err.Error(), "dirty") {
		t.Fatalf("BaselineV1() error = %v, want dirty-state rejection", err)
	}
}

func TestBaselineV1RejectsMissingRequiredConstraint(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	applyUnversionedV1Schema(t, databaseURL)

	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.ExecContext(context.Background(), `
		ALTER TABLE oauth_refresh_tokens
		DROP CONSTRAINT uq_oauth_refresh_tokens_family_sequence
	`); err != nil {
		t.Fatalf("drop required constraint: %v", err)
	}

	err := migration.BaselineV1(context.Background(), databaseURL)
	if err == nil {
		t.Fatal("BaselineV1() error = nil, want missing-constraint rejection")
	}
	if !strings.Contains(err.Error(), "required unique constraint") {
		t.Fatalf("BaselineV1() error = %v, want missing unique constraint", err)
	}
	assertUnversioned(t, databaseURL)
}

func TestBaselineV1RejectsIncompatibleCatalogObjects(t *testing.T) {
	tests := []struct {
		name      string
		mutate    string
		wantError string
	}{
		{
			name:      "column default",
			mutate:    `ALTER TABLE audit_logs ALTER COLUMN success SET DEFAULT FALSE`,
			wantError: `required default "audit_logs"."success"`,
		},
		{
			name: "partial index predicate",
			mutate: `
				DROP INDEX uq_identities_user_github;
				CREATE UNIQUE INDEX uq_identities_user_github
					ON identities(user_id, provider) WHERE provider = 'lark';
			`,
			wantError: `required index "uq_identities_user_github"`,
		},
		{
			name: "narrowed partial index predicate",
			mutate: `
				DROP INDEX uq_identities_user_github;
				CREATE UNIQUE INDEX uq_identities_user_github
					ON identities(user_id, provider)
					WHERE provider = 'github' AND user_id > 0;
			`,
			wantError: `required index "uq_identities_user_github"`,
		},
		{
			name: "weakened check constraint",
			mutate: `
				ALTER TABLE oauth_clients DROP CONSTRAINT ck_oauth_clients_redirect_uris;
				ALTER TABLE oauth_clients ADD CONSTRAINT ck_oauth_clients_redirect_uris
					CHECK (COALESCE(array_length(redirect_uris, 1), 0) >= 0);
			`,
			wantError: `required check constraint`,
		},
		{
			name: "changed challenge method literal",
			mutate: `
				ALTER TABLE oauth_authorizations DROP CONSTRAINT ck_oauth_authorizations_challenge_method;
				ALTER TABLE oauth_authorizations ADD CONSTRAINT ck_oauth_authorizations_challenge_method
					CHECK (code_challenge_method IN ('s256', 'plain'));
			`,
			wantError: `required check constraint`,
		},
		{
			name: "weakened challenge constraint with suffix",
			mutate: `
				ALTER TABLE oauth_authorizations DROP CONSTRAINT ck_oauth_authorizations_challenge_method;
				ALTER TABLE oauth_authorizations ADD CONSTRAINT ck_oauth_authorizations_challenge_method
					CHECK (code_challenge_method IN ('S256', 'plain') OR TRUE);
			`,
			wantError: `required check constraint`,
		},
		{
			name:      "replica trigger",
			mutate:    `ALTER TABLE "user" ENABLE REPLICA TRIGGER trg_user_email_domain`,
			wantError: `required trigger "trg_user_email_domain"`,
		},
		{
			name: "conditional trigger",
			mutate: `
				DROP TRIGGER trg_user_email_domain ON "user";
				CREATE TRIGGER trg_user_email_domain
					BEFORE INSERT OR UPDATE OF login_email ON "user"
					FOR EACH ROW WHEN (false)
					EXECUTE FUNCTION auto_set_email_type();
			`,
			wantError: `required trigger "trg_user_email_domain"`,
		},
		{
			name: "trigger with extra event",
			mutate: `
				DROP TRIGGER trg_user_updated_at ON "user";
				CREATE TRIGGER trg_user_updated_at
					BEFORE UPDATE OR DELETE ON "user"
					FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
			`,
			wantError: `required trigger "trg_user_updated_at"`,
		},
		{
			name:      "trigger function configuration",
			mutate:    `ALTER FUNCTION check_other_mail_limit() SET search_path = pg_catalog`,
			wantError: `required trigger function "check_other_mail_limit"`,
		},
		{
			name: "no-op trigger function",
			mutate: `
				CREATE OR REPLACE FUNCTION auto_set_email_type() RETURNS trigger
				LANGUAGE plpgsql AS $$
				BEGIN
					RETURN NEW;
				END;
				$$;
			`,
			wantError: `required trigger function "auto_set_email_type"`,
		},
		{
			name:      "disabled trigger",
			mutate:    `ALTER TABLE "user" DISABLE TRIGGER trg_user_email_domain`,
			wantError: `required trigger "trg_user_email_domain"`,
		},
		{
			name: "wrong trigger function",
			mutate: `
				DROP TRIGGER trg_user_email_domain ON "user";
				CREATE TRIGGER trg_user_email_domain
					BEFORE INSERT OR UPDATE OF login_email ON "user"
					FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
			`,
			wantError: `required trigger "trg_user_email_domain"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			databaseURL := testutil.StartPostgres(t)
			applyUnversionedV1Schema(t, databaseURL)
			database := testutil.OpenSQL(t, databaseURL)
			t.Cleanup(func() { _ = database.Close() })
			if _, err := database.ExecContext(context.Background(), test.mutate); err != nil {
				t.Fatalf("mutate V001 catalog: %v", err)
			}

			err := migration.BaselineV1(context.Background(), databaseURL)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("BaselineV1() error = %v, want %q", err, test.wantError)
			}
			assertUnversioned(t, databaseURL)
		})
	}
}

func TestBaselineV1RejectsMissingRequiredTrigger(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	applyUnversionedV1Schema(t, databaseURL)

	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.ExecContext(context.Background(), `DROP TRIGGER trg_user_email_domain ON "user"`); err != nil {
		t.Fatalf("drop required trigger: %v", err)
	}

	err := migration.BaselineV1(context.Background(), databaseURL)
	if err == nil {
		t.Fatal("BaselineV1() error = nil, want missing-trigger rejection")
	}
	if !strings.Contains(err.Error(), `missing required trigger "trg_user_email_domain"`) {
		t.Fatalf("BaselineV1() error = %v, want missing trigger", err)
	}

	version, dirty, err := migration.Current(databaseURL)
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if version != 0 || dirty {
		t.Fatalf("Current() = (%d, %t), want (0, false)", version, dirty)
	}
}

func TestBaselineV1RejectsTriggerNameCollisionOnWrongTable(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	applyUnversionedV1Schema(t, databaseURL)

	database := testutil.OpenSQL(t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.ExecContext(context.Background(), `
		DROP TRIGGER trg_user_email_domain ON "user";
		CREATE TABLE trigger_name_collision (id BIGINT PRIMARY KEY);
		CREATE FUNCTION trigger_name_collision_function() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER trg_user_email_domain
			BEFORE INSERT ON trigger_name_collision
			FOR EACH ROW EXECUTE FUNCTION trigger_name_collision_function();
	`); err != nil {
		t.Fatalf("replace required trigger with same-name collision: %v", err)
	}

	err := migration.BaselineV1(context.Background(), databaseURL)
	if err == nil {
		t.Fatal("BaselineV1() error = nil, want wrong-table trigger rejection")
	}
	if !strings.Contains(err.Error(), `missing required trigger "trg_user_email_domain" on table "public"."user"`) {
		t.Fatalf("BaselineV1() error = %v, want missing trigger on public.user", err)
	}

	version, dirty, err := migration.Current(databaseURL)
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if version != 0 || dirty {
		t.Fatalf("Current() = (%d, %t), want (0, false)", version, dirty)
	}
}

func assertUnversioned(t *testing.T, databaseURL string) {
	t.Helper()

	version, dirty, err := migration.Current(databaseURL)
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if version != 0 || dirty {
		t.Fatalf("Current() = (%d, %t), want (0, false)", version, dirty)
	}
}

func TestBaselineV1RegistersExistingSchema(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	applyUnversionedV1Schema(t, databaseURL)

	if err := migration.BaselineV1(context.Background(), databaseURL); err != nil {
		t.Fatalf("BaselineV1() error = %v", err)
	}

	version, dirty, err := migration.Current(databaseURL)
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if version != 1 || dirty {
		t.Fatalf("Current() = (%d, %t), want (1, false)", version, dirty)
	}

	if err := migration.BaselineV1(context.Background(), databaseURL); err != nil {
		t.Fatalf("BaselineV1() idempotent error = %v", err)
	}
}
