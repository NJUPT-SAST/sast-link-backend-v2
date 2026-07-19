package migration

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
)

type requiredEnum struct {
	name   string
	labels []string
}

var requiredEnums = []requiredEnum{
	{name: "user_role_enum", labels: []string{"freshman", "member", "lecturer", "admin"}},
	{name: "department_enum", labels: []string{"software", "media"}},
	{name: "login_method_enum", labels: []string{"github", "lark", "other_mail"}},
	{name: "state_enum", labels: []string{"is_deleted", "on_sast", "retired_sast", "njupter"}},
	{name: "email_enum", labels: []string{"sast_email", "njupt_email"}},
	{name: "client_enum", labels: []string{"first_party", "third_party"}},
	{name: "college_enum", labels: []string{
		"贝尔英才学院", "通信与信息工程学院", "电光柔学院",
		"集成电路科学与工程学院（产教融合学院）", "计算机学院、软件学院、网络空间安全学院",
		"自动化学院", "人工智能学院", "材料科学与工程学院", "化学与生命科学学院",
		"物联网学院", "理学院", "现代邮政学院、智慧交通学院", "数字媒体与设计艺术学院",
		"管理学院", "经济学院", "社会与人口学院、社会工作学院", "外国语学院",
		"教育科学与技术学院", "波特兰学院", "其他",
	}},
}

const enumLabelsQuery = `SELECT enum.enumlabel
FROM pg_catalog.pg_enum enum
JOIN pg_catalog.pg_type typ ON typ.oid = enum.enumtypid
JOIN pg_catalog.pg_namespace namespace ON namespace.oid = typ.typnamespace
WHERE namespace.nspname = 'public' AND typ.typname = $1
ORDER BY enum.enumsortorder`

func requireV1Enums(ctx context.Context, database *sql.DB) error {
	for _, required := range requiredEnums {
		rows, err := database.QueryContext(ctx, enumLabelsQuery, required.name)
		if err != nil {
			return fmt.Errorf("check required enum %q: %w", required.name, err)
		}
		labels := make([]string, 0, len(required.labels))
		for rows.Next() {
			var label string
			if err := rows.Scan(&label); err != nil {
				_ = rows.Close() //nolint:sqlclosecheck // Close immediately on scan failure; normal path checks Close below.
				return fmt.Errorf("scan required enum %q: %w", required.name, err)
			}
			labels = append(labels, label)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close required enum %q rows: %w", required.name, err)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("read required enum %q: %w", required.name, err)
		}
		if !slices.Equal(labels, required.labels) {
			return fmt.Errorf("required enum %q labels = %q, want %q", required.name, labels, required.labels)
		}
	}
	return nil
}

type requiredColumn struct {
	table      string
	name       string
	dataType   string
	notNull    bool
	hasDefault bool
}

var requiredColumns = []requiredColumn{
	{table: "user", name: "id", dataType: "bigint", notNull: true, hasDefault: true},
	{table: "user", name: "role", dataType: "user_role_enum", notNull: true, hasDefault: true},
	{table: "user", name: "name", dataType: "character varying(255)", notNull: true},
	{table: "user", name: "phone_number", dataType: "character varying(20)", notNull: true},
	{table: "user", name: "qq_number", dataType: "character varying(20)", notNull: true},
	{table: "user", name: "password", dataType: "character varying(512)", notNull: true},
	{table: "user", name: "student_id", dataType: "character varying(50)", notNull: true},
	{table: "user", name: "state", dataType: "state_enum", notNull: true, hasDefault: true},
	{table: "user", name: "email_type", dataType: "email_enum", notNull: true},
	{table: "user", name: "login_email", dataType: "character varying(255)", notNull: true},
	{table: "user", name: "created_at", dataType: "timestamp with time zone", notNull: true, hasDefault: true},
	{table: "user", name: "updated_at", dataType: "timestamp with time zone", notNull: true, hasDefault: true},
	{table: "user", name: "college", dataType: "college_enum", notNull: true, hasDefault: true},
	{table: "user", name: "major", dataType: "character varying(50)", notNull: true, hasDefault: true},
	{table: "user", name: "token_version", dataType: "integer", notNull: true, hasDefault: true},
	{table: "oauth_clients", name: "id", dataType: "bigint", notNull: true, hasDefault: true},
	{table: "oauth_clients", name: "client_id", dataType: "character varying(255)", notNull: true},
	{table: "oauth_clients", name: "client_secret", dataType: "character varying(255)"},
	{table: "oauth_clients", name: "client_name", dataType: "character varying(255)", notNull: true},
	{table: "oauth_clients", name: "client_type", dataType: "client_enum", notNull: true},
	{table: "oauth_clients", name: "redirect_uris", dataType: "text[]", notNull: true},
	{table: "oauth_clients", name: "grant_types", dataType: "text[]", notNull: true},
	{table: "oauth_clients", name: "scopes", dataType: "text[]", notNull: true, hasDefault: true},
	{table: "oauth_clients", name: "is_active", dataType: "boolean", notNull: true, hasDefault: true},
	{table: "oauth_clients", name: "created_at", dataType: "timestamp with time zone", notNull: true, hasDefault: true},
	{table: "oauth_clients", name: "updated_at", dataType: "timestamp with time zone", notNull: true, hasDefault: true},
	{table: "profile", name: "id", dataType: "bigint", notNull: true, hasDefault: true},
	{table: "profile", name: "user_id", dataType: "bigint", notNull: true},
	{table: "profile", name: "nickname", dataType: "character varying(255)"},
	{table: "profile", name: "department", dataType: "department_enum"},
	{table: "profile", name: "intro", dataType: "character varying(255)"},
	{table: "profile", name: "email", dataType: "character varying(255)"},
	{table: "profile", name: "avatar", dataType: "character varying(512)"},
	{table: "profile", name: "blog_url", dataType: "character varying(512)"},
	{table: "profile", name: "github_url", dataType: "character varying(512)"},
	{table: "profile", name: "created_at", dataType: "timestamp with time zone", notNull: true, hasDefault: true},
	{table: "profile", name: "updated_at", dataType: "timestamp with time zone", notNull: true, hasDefault: true},
	{table: "identities", name: "id", dataType: "bigint", notNull: true, hasDefault: true},
	{table: "identities", name: "user_id", dataType: "bigint", notNull: true},
	{table: "identities", name: "provider", dataType: "login_method_enum", notNull: true},
	{table: "identities", name: "provider_id", dataType: "character varying(255)", notNull: true},
	{table: "identities", name: "identity_data", dataType: "jsonb"},
	{table: "identities", name: "access_token", dataType: "text"},
	{table: "identities", name: "refresh_token", dataType: "text"},
	{table: "identities", name: "token_expires_at", dataType: "timestamp with time zone"},
	{table: "identities", name: "created_at", dataType: "timestamp with time zone", notNull: true, hasDefault: true},
	{table: "identities", name: "updated_at", dataType: "timestamp with time zone", notNull: true, hasDefault: true},
	{table: "oauth_authorizations", name: "id", dataType: "bigint", notNull: true, hasDefault: true},
	{table: "oauth_authorizations", name: "code", dataType: "character varying(255)", notNull: true},
	{table: "oauth_authorizations", name: "client_id", dataType: "bigint", notNull: true},
	{table: "oauth_authorizations", name: "user_id", dataType: "bigint", notNull: true},
	{table: "oauth_authorizations", name: "redirect_uri", dataType: "character varying(2048)"},
	{table: "oauth_authorizations", name: "scopes", dataType: "text[]"},
	{table: "oauth_authorizations", name: "code_challenge", dataType: "character varying(255)", notNull: true},
	{table: "oauth_authorizations", name: "code_challenge_method", dataType: "character varying(10)", notNull: true},
	{table: "oauth_authorizations", name: "nonce", dataType: "character varying(255)"},
	{table: "oauth_authorizations", name: "is_used", dataType: "boolean", notNull: true, hasDefault: true},
	{table: "oauth_authorizations", name: "family_id", dataType: "character varying(255)"},
	{table: "oauth_authorizations", name: "expires_at", dataType: "timestamp with time zone", notNull: true},
	{table: "oauth_authorizations", name: "created_at", dataType: "timestamp with time zone", notNull: true, hasDefault: true},
	{table: "oauth_access_tokens", name: "id", dataType: "bigint", notNull: true, hasDefault: true},
	{table: "oauth_access_tokens", name: "token_id", dataType: "character varying(255)", notNull: true},
	{table: "oauth_access_tokens", name: "client_id", dataType: "bigint", notNull: true},
	{table: "oauth_access_tokens", name: "user_id", dataType: "bigint", notNull: true},
	{table: "oauth_access_tokens", name: "family_id", dataType: "character varying(255)"},
	{table: "oauth_access_tokens", name: "scopes", dataType: "text[]"},
	{table: "oauth_access_tokens", name: "revoked_at", dataType: "timestamp with time zone"},
	{table: "oauth_access_tokens", name: "expires_at", dataType: "timestamp with time zone", notNull: true},
	{table: "oauth_access_tokens", name: "created_at", dataType: "timestamp with time zone", notNull: true, hasDefault: true},
	{table: "oauth_refresh_tokens", name: "id", dataType: "bigint", notNull: true, hasDefault: true},
	{table: "oauth_refresh_tokens", name: "token_hash", dataType: "character varying(255)", notNull: true},
	{table: "oauth_refresh_tokens", name: "family_id", dataType: "character varying(255)", notNull: true},
	{table: "oauth_refresh_tokens", name: "sequence", dataType: "integer", notNull: true, hasDefault: true},
	{table: "oauth_refresh_tokens", name: "client_id", dataType: "bigint", notNull: true},
	{table: "oauth_refresh_tokens", name: "user_id", dataType: "bigint", notNull: true},
	{table: "oauth_refresh_tokens", name: "scopes", dataType: "text[]"},
	{table: "oauth_refresh_tokens", name: "revoked_at", dataType: "timestamp with time zone"},
	{table: "oauth_refresh_tokens", name: "expires_at", dataType: "timestamp with time zone", notNull: true},
	{table: "oauth_refresh_tokens", name: "created_at", dataType: "timestamp with time zone", notNull: true, hasDefault: true},
	{table: "audit_logs", name: "id", dataType: "bigint", notNull: true, hasDefault: true},
	{table: "audit_logs", name: "user_id", dataType: "bigint"},
	{table: "audit_logs", name: "action", dataType: "character varying(50)", notNull: true},
	{table: "audit_logs", name: "resource", dataType: "character varying(50)", notNull: true},
	{table: "audit_logs", name: "resource_id", dataType: "character varying(255)"},
	{table: "audit_logs", name: "detail", dataType: "jsonb", hasDefault: true},
	{table: "audit_logs", name: "client_ip", dataType: "inet"},
	{table: "audit_logs", name: "user_agent", dataType: "text"},
	{table: "audit_logs", name: "success", dataType: "boolean", notNull: true, hasDefault: true},
	{table: "audit_logs", name: "err_code", dataType: "integer"},
	{table: "audit_logs", name: "created_at", dataType: "timestamp with time zone", notNull: true, hasDefault: true},
}

const columnQuery = `SELECT pg_catalog.format_type(attribute.atttypid, attribute.atttypmod),
       attribute.attnotnull,
       default_value.adbin IS NOT NULL
FROM pg_catalog.pg_attribute attribute
JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
LEFT JOIN pg_catalog.pg_attrdef default_value
  ON default_value.adrelid = relation.oid AND default_value.adnum = attribute.attnum
WHERE namespace.nspname = 'public'
  AND relation.relname = $1
  AND attribute.attname = $2
  AND attribute.attnum > 0
  AND NOT attribute.attisdropped`

func requireV1Columns(ctx context.Context, database *sql.DB) error {
	for _, required := range requiredColumns {
		var dataType string
		var notNull bool
		var hasDefault bool
		err := database.QueryRowContext(ctx, columnQuery, required.table, required.name).
			Scan(&dataType, &notNull, &hasDefault)
		if err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf("missing required column %q.%q", required.table, required.name)
			}
			return fmt.Errorf("check required column %q.%q: %w", required.table, required.name, err)
		}
		dataType = strings.TrimPrefix(dataType, "public.")
		if dataType != required.dataType || notNull != required.notNull || hasDefault != required.hasDefault {
			return fmt.Errorf(
				"required column %q.%q = (%s, not null %t, default %t), want (%s, not null %t, default %t)",
				required.table, required.name, dataType, notNull, hasDefault,
				required.dataType, required.notNull, required.hasDefault,
			)
		}
	}
	return nil
}

type requiredDefault struct {
	table     string
	column    string
	value     string
	substring bool
}

var requiredDefaults = []requiredDefault{
	{table: "user", column: "id", value: "nextval", substring: true},
	{table: "user", column: "role", value: "'freshman'"},
	{table: "user", column: "state", value: "'njupter'"},
	{table: "user", column: "college", value: "'其他'"},
	{table: "user", column: "major", value: "''"},
	{table: "user", column: "token_version", value: "0"},
	{table: "oauth_clients", column: "id", value: "nextval", substring: true},
	{table: "oauth_clients", column: "scopes", value: "'{}'"},
	{table: "oauth_clients", column: "is_active", value: "true"},
	{table: "profile", column: "id", value: "nextval", substring: true},
	{table: "identities", column: "id", value: "nextval", substring: true},
	{table: "oauth_authorizations", column: "id", value: "nextval", substring: true},
	{table: "oauth_authorizations", column: "is_used", value: "false"},
	{table: "oauth_access_tokens", column: "id", value: "nextval", substring: true},
	{table: "oauth_refresh_tokens", column: "id", value: "nextval", substring: true},
	{table: "oauth_refresh_tokens", column: "sequence", value: "0"},
	{table: "audit_logs", column: "id", value: "nextval", substring: true},
	{table: "audit_logs", column: "detail", value: "'{}'"},
	{table: "audit_logs", column: "success", value: "true"},
}

const defaultExpressionQuery = `SELECT pg_catalog.pg_get_expr(default_value.adbin, default_value.adrelid)
FROM pg_catalog.pg_attrdef default_value
JOIN pg_catalog.pg_class relation ON relation.oid = default_value.adrelid
JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
JOIN pg_catalog.pg_attribute attribute
  ON attribute.attrelid = relation.oid AND attribute.attnum = default_value.adnum
WHERE namespace.nspname = 'public' AND relation.relname = $1 AND attribute.attname = $2`

func requireV1Defaults(ctx context.Context, database *sql.DB) error {
	for _, required := range requiredDefaults {
		var expression string
		if err := database.QueryRowContext(ctx, defaultExpressionQuery, required.table, required.column).
			Scan(&expression); err != nil {
			return fmt.Errorf("check required default %q.%q: %w", required.table, required.column, err)
		}
		normalized := normalizeDefaultExpression(expression)
		matches := normalized == required.value
		if required.substring {
			matches = strings.Contains(normalized, required.value)
		}
		if !matches {
			return fmt.Errorf(
				"required default %q.%q = %q, want semantic value %q",
				required.table, required.column, expression, required.value,
			)
		}
	}
	return nil
}

func normalizeDefaultExpression(expression string) string {
	expression = strings.ToLower(strings.Join(strings.Fields(expression), ""))
	for _, typeCast := range []string{
		"::public.character varying", "::character varying",
		"::public.user_role_enum", "::user_role_enum",
		"::public.state_enum", "::state_enum",
		"::public.college_enum", "::college_enum",
		"::pg_catalog.text[]", "::text[]",
		"::pg_catalog.jsonb", "::jsonb",
	} {
		expression = strings.ReplaceAll(expression, strings.ReplaceAll(typeCast, " ", ""), "")
	}
	return strings.Trim(expression, "()")
}
