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
	{table: "oauth_clients", kind: "c", check: "COALESCE(array_length(redirect_uris, 1), 0) > 0"},
	{table: "oauth_clients", kind: "c", check: "COALESCE(array_length(grant_types, 1), 0) > 0"},
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
	{
		table: "oauth_authorizations",
		kind:  "c",
		check: "(code_challenge_method)::text = ANY ((ARRAY['S256'::character varying, 'plain'::character varying])::text[])",
	},
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

const constraintQuery = `SELECT pg_catalog.pg_get_constraintdef(con.oid)
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
    AND ($5 = '' OR con.confdeltype = $5::"char")`

func requireV1Constraints(ctx context.Context, database *sql.DB) error {
	for _, required := range requiredConstraints {
		rows, err := database.QueryContext(
			ctx,
			constraintQuery,
			required.table,
			required.kind,
			required.columns,
			required.reference,
			required.deleteAction,
		)
		if err != nil {
			return fmt.Errorf("check required constraint on %q (%s): %w", required.table, required.columns, err)
		}

		found := false
		for rows.Next() {
			var definition string
			if err := rows.Scan(&definition); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan required constraint on %q (%s): %w", required.table, required.columns, err)
			}
			if required.check == "" || checkConstraintExpressionEqual(definition, required.check) {
				found = true
			}
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close required constraint rows on %q (%s): %w", required.table, required.columns, err)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("read required constraint on %q (%s): %w", required.table, required.columns, err)
		}
		if !found {
			return fmt.Errorf(
				"missing required %s constraint on %q (%s)",
				constraintKind(required.kind), required.table, required.columns,
			)
		}
	}
	return nil
}

func checkConstraintExpressionEqual(definition string, required string) bool {
	definition = strings.TrimSpace(definition)
	if len(definition) >= len("CHECK") && strings.EqualFold(definition[:len("CHECK")], "CHECK") {
		definition = strings.TrimSpace(definition[len("CHECK"):])
	}
	return semanticExpressionEqual(definition, required)
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
				"required index %q on %q has incompatible definition: predicate %q normalized %q want %q normalized %q",
				required.name, required.table, predicate, normalizeCatalogExpression(predicate), required.predicate, normalizeCatalogExpression(required.predicate),
			)
		}
	}
	return nil
}

func semanticExpressionEqual(actual string, required string) bool {
	return normalizeCatalogExpression(actual) == normalizeCatalogExpression(required)
}

func normalizeCatalogExpression(expression string) string {
	var normalized strings.Builder
	normalized.Grow(len(expression))
	inQuote := false
	for index := 0; index < len(expression); index++ {
		character := expression[index]
		if character == '\'' {
			normalized.WriteByte(character)
			if inQuote && index+1 < len(expression) && expression[index+1] == '\'' {
				normalized.WriteByte(expression[index+1])
				index++
				continue
			}
			inQuote = !inQuote
			continue
		}
		if !inQuote {
			if strings.ContainsRune(" \t\r\n\f\v", rune(character)) {
				continue
			}
			if character >= 'A' && character <= 'Z' {
				character += 'a' - 'A'
			}
		}
		normalized.WriteByte(character)
	}
	return canonicalizeTextArrayAny(trimRedundantOuterParentheses(stripCatalogCasts(normalized.String())))
}

func canonicalizeTextArrayAny(expression string) string {
	expression = trimRedundantOuterParentheses(expression)
	anyIndex := strings.Index(expression, "=any(")
	if anyIndex < 0 {
		return expression
	}
	openIndex := anyIndex + len("=any")
	closeIndex := matchingClosingParenthesis(expression, openIndex)
	if closeIndex < 0 {
		return expression
	}
	argument := trimRedundantOuterParentheses(expression[openIndex+1 : closeIndex])
	if !strings.HasPrefix(argument, "array[") {
		return expression
	}
	argument = strings.ReplaceAll(argument, "[('", "['")
	argument = strings.ReplaceAll(argument, "'),('", "','")
	argument = strings.ReplaceAll(argument, "')]", "']")
	return expression[:openIndex+1] + argument + expression[closeIndex:]
}

func matchingClosingParenthesis(expression string, openIndex int) int {
	if openIndex >= len(expression) || expression[openIndex] != '(' {
		return -1
	}
	depth := 0
	inQuote := false
	for index := openIndex; index < len(expression); index++ {
		character := expression[index]
		if character == '\'' {
			if inQuote && index+1 < len(expression) && expression[index+1] == '\'' {
				index++
				continue
			}
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		switch character {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func stripCatalogCasts(expression string) string {
	casts := []string{
		"::public.charactervarying", "::charactervarying",
		"::public.login_method_enum", "::login_method_enum",
		"::public.text", "::text",
	}
	var normalized strings.Builder
	normalized.Grow(len(expression))
	inQuote := false
	for index := 0; index < len(expression); {
		if expression[index] == '\'' {
			normalized.WriteByte(expression[index])
			if inQuote && index+1 < len(expression) && expression[index+1] == '\'' {
				normalized.WriteByte(expression[index+1])
				index += 2
				continue
			}
			inQuote = !inQuote
			index++
			continue
		}
		if !inQuote {
			removed := false
			for _, cast := range casts {
				if strings.HasPrefix(expression[index:], cast) {
					index += len(cast)
					removed = true
					break
				}
			}
			if removed {
				continue
			}
		}
		normalized.WriteByte(expression[index])
		index++
	}
	return normalized.String()
}

func trimRedundantOuterParentheses(expression string) string {
	for hasOuterParentheses(expression) {
		expression = expression[1 : len(expression)-1]
	}
	return expression
}

func hasOuterParentheses(expression string) bool {
	if len(expression) < 2 || expression[0] != '(' || expression[len(expression)-1] != ')' {
		return false
	}
	depth := 0
	inQuote := false
	for index, character := range expression {
		if character == '\'' {
			if inQuote && index+1 < len(expression) && expression[index+1] == '\'' {
				continue
			}
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		switch character {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && index != len(expression)-1 {
				return false
			}
		}
	}
	return depth == 0 && !inQuote
}
