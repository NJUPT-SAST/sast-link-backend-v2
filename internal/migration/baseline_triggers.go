package migration

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"unicode"
)

type requiredFunction struct {
	name   string
	source string
}

var requiredFunctions = []requiredFunction{
	{
		name: "update_updated_at_column",
		source: `BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;`,
	},
	{
		name: "check_other_mail_limit",
		source: `DECLARE
    mail_count INT;
BEGIN
    IF NEW.provider = 'other_mail' THEN
        SELECT COUNT(*) INTO mail_count
        FROM identities
        WHERE user_id = NEW.user_id AND provider = 'other_mail';
        IF mail_count >= 2 THEN
            RAISE EXCEPTION 'Each user can bind at most 2 additional emails.';
        END IF;
    END IF;
    RETURN NEW;
END;`,
	},
	{
		name: "auto_set_email_type",
		source: `BEGIN
    IF LOWER(NEW.login_email) LIKE '%@sast.fun' THEN
        NEW.email_type := 'sast_email';
    ELSIF LOWER(NEW.login_email) LIKE '%@njupt.edu.cn' THEN
        NEW.email_type := 'njupt_email';
    ELSE
        RAISE EXCEPTION 'Invalid email domain: %. Only @njupt.edu.cn and @sast.fun are allowed.', NEW.login_email;
    END IF;
    RETURN NEW;
END;`,
	},
}

const functionQuery = `SELECT function.prosrc
  FROM pg_catalog.pg_proc function
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_language language ON language.oid = function.prolang
  WHERE namespace.nspname = 'public'
    AND function.proname = $1
    AND function.pronargs = 0
    AND function.prorettype = 'pg_catalog.trigger'::pg_catalog.regtype
    AND language.lanname = 'plpgsql'
    AND function.proconfig IS NULL`

func requireV1Functions(ctx context.Context, database *sql.DB) error {
	for _, required := range requiredFunctions {
		var source string
		err := database.QueryRowContext(ctx, functionQuery, required.name).Scan(&source)
		if err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf("missing required trigger function %q", required.name)
			}
			return fmt.Errorf("check required function %q: %w", required.name, err)
		}
		if normalizeFunctionSource(source) != normalizeFunctionSource(required.source) {
			return fmt.Errorf("required trigger function %q has incompatible definition", required.name)
		}
	}
	return nil
}

func normalizeFunctionSource(source string) string {
	var normalized strings.Builder
	normalized.Grow(len(source))
	inQuote := false
	for index := 0; index < len(source); index++ {
		character := source[index]
		if character == '\'' {
			normalized.WriteByte(character)
			if inQuote && index+1 < len(source) && source[index+1] == '\'' {
				normalized.WriteByte(source[index+1])
				index++
				continue
			}
			inQuote = !inQuote
			continue
		}
		if !inQuote && unicode.IsSpace(rune(character)) {
			continue
		}
		normalized.WriteByte(character)
	}
	return normalized.String()
}

type requiredTrigger struct {
	name         string
	table        string
	function     string
	timing       string
	insert       bool
	update       bool
	updateColumn string
}

var requiredTriggers = []requiredTrigger{
	{name: "trg_user_updated_at", table: "user", function: "update_updated_at_column", timing: "before", update: true},
	{name: "trg_profile_updated_at", table: "profile", function: "update_updated_at_column", timing: "before", update: true},
	{name: "trg_identities_updated_at", table: "identities", function: "update_updated_at_column", timing: "before", update: true},
	{name: "trg_oauth_clients_updated_at", table: "oauth_clients", function: "update_updated_at_column", timing: "before", update: true},
	{name: "trg_identities_other_mail_limit", table: "identities", function: "check_other_mail_limit", timing: "before", insert: true},
	{name: "trg_user_email_domain", table: "user", function: "auto_set_email_type", timing: "before", insert: true, update: true, updateColumn: "login_email"},
}

const triggerQuery = `SELECT trigger.tgenabled,
       (trigger.tgtype & 1) <> 0,
       (trigger.tgtype & 2) <> 0,
       (trigger.tgtype & 4) <> 0,
       (trigger.tgtype & 8) <> 0,
       (trigger.tgtype & 16) <> 0,
       (trigger.tgtype & 32) <> 0,
       function.proname,
       function_namespace.nspname,
       COALESCE((
         SELECT string_agg(attribute.attname, ',' ORDER BY column_number.ordinality)
         FROM unnest(trigger.tgattr::smallint[]) WITH ORDINALITY AS column_number(attnum, ordinality)
         JOIN pg_catalog.pg_attribute attribute
           ON attribute.attrelid = trigger.tgrelid AND attribute.attnum = column_number.attnum
       ), ''),
       trigger.tgqual IS NULL
FROM pg_catalog.pg_trigger trigger
JOIN pg_catalog.pg_class relation ON relation.oid = trigger.tgrelid
JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
JOIN pg_catalog.pg_proc function ON function.oid = trigger.tgfoid
JOIN pg_catalog.pg_namespace function_namespace ON function_namespace.oid = function.pronamespace
WHERE NOT trigger.tgisinternal
  AND trigger.tgname = $1
  AND relation.relname = $2
  AND namespace.nspname = 'public'`

func requireV1Triggers(ctx context.Context, database *sql.DB) error {
	for _, required := range requiredTriggers {
		var enabled, functionName, functionSchema, updateColumns string
		var rowLevel, before, insert, deleteEvent, update, truncate, unconditional bool
		err := database.QueryRowContext(ctx, triggerQuery, required.name, required.table).
			Scan(
				&enabled,
				&rowLevel,
				&before,
				&insert,
				&deleteEvent,
				&update,
				&truncate,
				&functionName,
				&functionSchema,
				&updateColumns,
				&unconditional,
			)
		if err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf("missing required trigger %q on table %q.%q", required.name, "public", required.table)
			}
			return fmt.Errorf("check required trigger %q on %q: %w", required.name, required.table, err)
		}
		if enabled != "O" || !rowLevel || before != (required.timing == "before") ||
			insert != required.insert || update != required.update || deleteEvent || truncate || !unconditional ||
			functionName != required.function || functionSchema != "public" ||
			updateColumns != required.updateColumn {
			return fmt.Errorf("required trigger %q on %q has incompatible definition", required.name, required.table)
		}
	}
	return nil
}
