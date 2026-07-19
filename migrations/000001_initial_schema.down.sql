DROP TRIGGER IF EXISTS trg_user_email_domain ON "user";
DROP TRIGGER IF EXISTS trg_identities_other_mail_limit ON identities;
DROP TRIGGER IF EXISTS trg_oauth_clients_updated_at ON oauth_clients;
DROP TRIGGER IF EXISTS trg_identities_updated_at ON identities;
DROP TRIGGER IF EXISTS trg_profile_updated_at ON profile;
DROP TRIGGER IF EXISTS trg_user_updated_at ON "user";

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS oauth_refresh_tokens;
DROP TABLE IF EXISTS oauth_access_tokens;
DROP TABLE IF EXISTS oauth_authorizations;
DROP TABLE IF EXISTS identities;
DROP TABLE IF EXISTS profile;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS "user";

DROP FUNCTION IF EXISTS auto_set_email_type();
DROP FUNCTION IF EXISTS check_other_mail_limit();
DROP FUNCTION IF EXISTS update_updated_at_column();

DROP TYPE IF EXISTS college_enum;
DROP TYPE IF EXISTS client_enum;
DROP TYPE IF EXISTS email_enum;
DROP TYPE IF EXISTS state_enum;
DROP TYPE IF EXISTS login_method_enum;
DROP TYPE IF EXISTS department_enum;
DROP TYPE IF EXISTS user_role_enum;
