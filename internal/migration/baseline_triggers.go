package migration

import (
	"context"
	"database/sql"
	"fmt"
)

type requiredFunction struct {
	name string
}

var requiredFunctions = []requiredFunction{
	{name: "update_updated_at_column"},
	{name: "check_other_mail_limit"},
	{name: "auto_set_email_type"},
}

const functionQuery = `SELECT EXISTS (
  SELECT 1
  FROM pg_catalog.pg_proc function
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_language language ON language.oid = function.prolang
  WHERE namespace.nspname = 'public'
    AND function.proname = $1
    AND function.pronargs = 0
    AND function.prorettype = 'pg_catalog.trigger'::pg_catalog.regtype
    AND language.lanname = 'plpgsql'
)`

func requireV1Functions(ctx context.Context, database *sql.DB) error {
	for _, required := range requiredFunctions {
		var exists bool
		if err := database.QueryRowContext(ctx, functionQuery, required.name).Scan(&exists); err != nil {
			return fmt.Errorf("check required function %q: %w", required.name, err)
		}
		if !exists {
			return fmt.Errorf("missing required trigger function %q", required.name)
		}
	}
	return nil
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
       (trigger.tgtype & 16) <> 0,
       function.proname,
       function_namespace.nspname,
       COALESCE((
         SELECT string_agg(attribute.attname, ',' ORDER BY column_number.ordinality)
         FROM unnest(trigger.tgattr::smallint[]) WITH ORDINALITY AS column_number(attnum, ordinality)
         JOIN pg_catalog.pg_attribute attribute
           ON attribute.attrelid = trigger.tgrelid AND attribute.attnum = column_number.attnum
       ), '')
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
		var rowLevel, before, insert, update bool
		err := database.QueryRowContext(ctx, triggerQuery, required.name, required.table).
			Scan(&enabled, &rowLevel, &before, &insert, &update, &functionName, &functionSchema, &updateColumns)
		if err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf("missing required trigger %q on table %q.%q", required.name, "public", required.table)
			}
			return fmt.Errorf("check required trigger %q on %q: %w", required.name, required.table, err)
		}
		if enabled == "D" || !rowLevel || before != (required.timing == "before") ||
			insert != required.insert || update != required.update ||
			functionName != required.function || functionSchema != "public" ||
			updateColumns != required.updateColumn {
			return fmt.Errorf("required trigger %q on %q has incompatible definition", required.name, required.table)
		}
	}
	return nil
}
