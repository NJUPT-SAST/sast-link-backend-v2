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
	if _, err := database.Exec(`DROP TABLE schema_migrations`); err != nil {
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
	if err := instance.Force(2); err != nil {
		t.Fatalf("Force(2) error = %v", err)
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
	if _, err := database.Exec(`UPDATE schema_migrations SET dirty = true`); err != nil {
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
	if _, err := database.Exec(`
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
			if _, err := database.Exec(test.mutate); err != nil {
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
	if _, err := database.Exec(`DROP TRIGGER trg_user_email_domain ON "user"`); err != nil {
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
	if _, err := database.Exec(`
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
