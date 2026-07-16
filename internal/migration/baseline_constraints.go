package migration

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type requiredConstraint struct {
	table        string
	kind         string
	columns      string
	reference    string
	deleteAction string
	check        string
}

var requiredConstraints = []requiredConstraint{
	{table: "user", kind: "p", columns: "id"},
	{table: "user", kind: "u", columns: "student_id"},
	{table: "user", kind: "u", columns: "login_email"},
	{table: "oauth_clients", kind: "p", columns: "id"},
	{table: "oauth_clients", kind: "u", columns: "client_id"},
	{table: "oauth_clients", kind: "c", check: "array_length(redirect_uris"},
	{table: "oauth_clients", kind: "c", check: "array_length(grant_types"},
	{table: "profile", kind: "p", columns: "id"},
	{table: "profile", kind: "u", columns: "user_id"},
	{table: "profile", kind: "f", columns: "user_id", reference: "user.id", deleteAction: "c"},
	{table: "identities", kind: "p", columns: "id"},
	{table: "identities", kind: "u", columns: "provider,provider_id"},
	{table: "identities", kind: "f", columns: "user_id", reference: "user.id", deleteAction: "c"},
	{table: "oauth_authorizations", kind: "p", columns: "id"},
	{table: "oauth_authorizations", kind: "u", columns: "code"},
	{table: "oauth_authorizations", kind: "f", columns: "client_id", reference: "oauth_clients.id", deleteAction: "c"},
	{table: "oauth_authorizations", kind: "f", columns: "user_id", reference: "user.id", deleteAction: "c"},
	{table: "oauth_authorizations", kind: "c", check: "expires_at > created_at"},
	{table: "oauth_authorizations", kind: "c", check: "code_challenge_method"},
	{table: "oauth_access_tokens", kind: "p", columns: "id"},
	{table: "oauth_access_tokens", kind: "u", columns: "token_id"},
	{table: "oauth_access_tokens", kind: "f", columns: "client_id", reference: "oauth_clients.id", deleteAction: "c"},
	{table: "oauth_access_tokens", kind: "f", columns: "user_id", reference: "user.id", deleteAction: "c"},
	{table: "oauth_refresh_tokens", kind: "p", columns: "id"},
	{table: "oauth_refresh_tokens", kind: "u", columns: "token_hash"},
	{table: "oauth_refresh_tokens", kind: "u", columns: "family_id,sequence"},
	{table: "oauth_refresh_tokens", kind: "f", columns: "client_id", reference: "oauth_clients.id", deleteAction: "c"},
	{table: "oauth_refresh_tokens", kind: "f", columns: "user_id", reference: "user.id", deleteAction: "c"},
	{table: "oauth_refresh_tokens", kind: "c", check: "expires_at > created_at"},
	{table: "audit_logs", kind: "p", columns: "id"},
	{table: "audit_logs", kind: "f", columns: "user_id", reference: "user.id", deleteAction: "n"},
}

const constraintQuery = `SELECT EXISTS (
  SELECT 1
  FROM pg_catalog.pg_constraint con
  JOIN pg_catalog.pg_class relation ON relation.oid = con.conrelid
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
  LEFT JOIN pg_catalog.pg_class reference_relation ON reference_relation.oid = con.confrelid
  WHERE namespace.nspname = 'public'
    AND relation.relname = $1
    AND con.contype = $2
    AND (
      $3 = '' OR (
        SELECT string_agg(attribute.attname, ',' ORDER BY key.ordinality)
        FROM unnest(con.conkey) WITH ORDINALITY AS key(attnum, ordinality)
        JOIN pg_catalog.pg_attribute attribute
          ON attribute.attrelid = con.conrelid AND attribute.attnum = key.attnum
      ) = $3
    )
    AND (
      $4 = '' OR reference_relation.relname || '.' || (
        SELECT string_agg(attribute.attname, ',' ORDER BY key.ordinality)
        FROM unnest(con.confkey) WITH ORDINALITY AS key(attnum, ordinality)
        JOIN pg_catalog.pg_attribute attribute
          ON attribute.attrelid = con.confrelid AND attribute.attnum = key.attnum
      ) = $4
    )
    AND ($5 = '' OR con.confdeltype = $5::"char")
    AND ($6 = '' OR position($6 in lower(pg_catalog.pg_get_constraintdef(con.oid))) > 0)
)`

func requireV1Constraints(ctx context.Context, database *sql.DB) error {
	for _, required := range requiredConstraints {
		var exists bool
		if err := database.QueryRowContext(
			ctx,
			constraintQuery,
			required.table,
			required.kind,
			required.columns,
			required.reference,
			required.deleteAction,
			strings.ToLower(required.check),
		).Scan(&exists); err != nil {
			return fmt.Errorf("check required constraint on %q (%s): %w", required.table, required.columns, err)
		}
		if !exists {
			return fmt.Errorf(
				"missing required %s constraint on %q (%s)",
				constraintKind(required.kind), required.table, required.columns,
			)
		}
	}
	return nil
}

func constraintKind(kind string) string {
	switch kind {
	case "p":
		return "primary key"
	case "u":
		return "unique"
	case "f":
		return "foreign key"
	case "c":
		return "check"
	default:
		return kind
	}
}

type requiredIndex struct {
	name      string
	table     string
	columns   string
	unique    bool
	predicate string
}

var requiredIndexes = []requiredIndex{
	{name: "idx_identities_user_id", table: "identities", columns: "user_id"},
	{name: "idx_identities_provider", table: "identities", columns: "provider"},
	{name: "uq_identities_user_github", table: "identities", columns: "user_id,provider", unique: true, predicate: "provider = 'github'"},
	{name: "uq_identities_user_lark", table: "identities", columns: "user_id,provider", unique: true, predicate: "provider = 'lark'"},
	{name: "idx_oauth_authorizations_expires_at", table: "oauth_authorizations", columns: "expires_at", predicate: "is_used = false"},
	{name: "idx_oauth_authorizations_client_id", table: "oauth_authorizations", columns: "client_id"},
	{name: "idx_oauth_authorizations_user_client", table: "oauth_authorizations", columns: "user_id,client_id"},
	{name: "idx_oauth_access_tokens_expires_at", table: "oauth_access_tokens", columns: "expires_at"},
	{name: "idx_oauth_access_tokens_user_id", table: "oauth_access_tokens", columns: "user_id"},
	{name: "idx_oauth_access_tokens_client_id", table: "oauth_access_tokens", columns: "client_id"},
	{name: "idx_oauth_access_tokens_family_id", table: "oauth_access_tokens", columns: "family_id"},
	{name: "idx_oauth_refresh_tokens_family_id", table: "oauth_refresh_tokens", columns: "family_id"},
	{name: "idx_oauth_refresh_tokens_user_id", table: "oauth_refresh_tokens", columns: "user_id"},
	{name: "idx_oauth_refresh_tokens_client_id", table: "oauth_refresh_tokens", columns: "client_id"},
	{name: "idx_oauth_refresh_tokens_expires_at", table: "oauth_refresh_tokens", columns: "expires_at", predicate: "revoked_at is not null"},
	{name: "idx_audit_logs_user_created", table: "audit_logs", columns: "user_id,created_at"},
	{name: "idx_audit_logs_action", table: "audit_logs", columns: "action"},
	{name: "idx_audit_logs_created_at", table: "audit_logs", columns: "created_at"},
	{name: "idx_audit_logs_action_created", table: "audit_logs", columns: "action,created_at"},
}

const indexQuery = `SELECT (
    SELECT string_agg(attribute.attname, ',' ORDER BY key.ordinality)
    FROM unnest(index.indkey::smallint[]) WITH ORDINALITY AS key(attnum, ordinality)
    JOIN pg_catalog.pg_attribute attribute
      ON attribute.attrelid = index.indrelid AND attribute.attnum = key.attnum
  ),
  index.indisunique,
  index.indisvalid,
  index.indisready,
  COALESCE(pg_catalog.pg_get_expr(index.indpred, index.indrelid), '')
FROM pg_catalog.pg_index index
JOIN pg_catalog.pg_class index_relation ON index_relation.oid = index.indexrelid
JOIN pg_catalog.pg_class table_relation ON table_relation.oid = index.indrelid
JOIN pg_catalog.pg_namespace namespace ON namespace.oid = table_relation.relnamespace
WHERE namespace.nspname = 'public' AND table_relation.relname = $1 AND index_relation.relname = $2`

func requireV1Indexes(ctx context.Context, database *sql.DB) error {
	for _, required := range requiredIndexes {
		var columns, predicate string
		var unique, valid, ready bool
		err := database.QueryRowContext(ctx, indexQuery, required.table, required.name).
			Scan(&columns, &unique, &valid, &ready, &predicate)
		if err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf("missing required index %q on %q", required.name, required.table)
			}
			return fmt.Errorf("check required index %q on %q: %w", required.name, required.table, err)
		}
		if columns != required.columns || unique != required.unique || !valid || !ready ||
			!semanticExpressionEqual(predicate, required.predicate) {
			return fmt.Errorf(
				"required index %q on %q has incompatible definition",
				required.name, required.table,
			)
		}
	}
	return nil
}

func semanticExpressionEqual(actual string, required string) bool {
	normalized := normalizeCatalogExpression(actual)
	required = normalizeCatalogExpression(required)
	return normalized == required || strings.Contains(normalized, required)
}

func normalizeCatalogExpression(expression string) string {
	expression = strings.ToLower(strings.Join(strings.Fields(expression), " "))
	expression = strings.ReplaceAll(expression, "::text", "")
	expression = strings.ReplaceAll(expression, "::character varying", "")
	expression = strings.ReplaceAll(expression, "(('", "('")
	expression = strings.ReplaceAll(expression, "'))", "')")
	return strings.Trim(expression, "()")
}
