CREATE TYPE user_role_enum AS ENUM ('freshman', 'member', 'lecturer', 'admin');
CREATE TYPE department_enum AS ENUM ('software', 'media');
CREATE TYPE login_method_enum AS ENUM ('github', 'lark', 'other_mail');
CREATE TYPE state_enum AS ENUM ('is_deleted', 'on_sast', 'retired_sast', 'njupter');
CREATE TYPE email_enum AS ENUM ('sast_email', 'njupt_email');
CREATE TYPE client_enum AS ENUM ('first_party', 'third_party');
CREATE TYPE college_enum AS ENUM (
    '贝尔英才学院',
    '通信与信息工程学院',
    '电光柔学院',
    '集成电路科学与工程学院（产教融合学院）',
    '计算机学院、软件学院、网络空间安全学院',
    '自动化学院',
    '人工智能学院',
    '材料科学与工程学院',
    '化学与生命科学学院',
    '物联网学院',
    '理学院',
    '现代邮政学院、智慧交通学院',
    '数字媒体与设计艺术学院',
    '管理学院',
    '经济学院',
    '社会与人口学院、社会工作学院',
    '外国语学院',
    '教育科学与技术学院',
    '波特兰学院',
    '其他'
);

CREATE TABLE "user" (
    id BIGSERIAL PRIMARY KEY,
    role user_role_enum NOT NULL DEFAULT 'freshman',
    name VARCHAR(255) NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    qq_number VARCHAR(20) NOT NULL,
    password VARCHAR(512) NOT NULL,
    student_id VARCHAR(50) UNIQUE,
    state state_enum NOT NULL DEFAULT 'njupter',
    email_type email_enum NOT NULL,
    login_email VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    college college_enum NOT NULL DEFAULT '其他',
    major VARCHAR(50) NOT NULL DEFAULT '',
    token_version INT NOT NULL DEFAULT 0
);

CREATE TABLE oauth_clients (
    id BIGSERIAL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret VARCHAR(255),
    client_name VARCHAR(255) NOT NULL,
    client_type client_enum NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    grant_types TEXT[] NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_oauth_clients_redirect_uris
        CHECK (COALESCE(array_length(redirect_uris, 1), 0) > 0),
    CONSTRAINT ck_oauth_clients_grant_types
        CHECK (COALESCE(array_length(grant_types, 1), 0) > 0)
);

CREATE TABLE profile (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE REFERENCES "user"(id) ON DELETE CASCADE,
    nickname VARCHAR(255),
    department department_enum,
    intro VARCHAR(255),
    email VARCHAR(255),
    avatar VARCHAR(512),
    blog_url VARCHAR(512),
    github_url VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE identities (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    provider login_method_enum NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    identity_data JSONB,
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_identities_provider_provider_id UNIQUE (provider, provider_id)
);

CREATE TABLE oauth_authorizations (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(255) NOT NULL UNIQUE,
    client_id BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    redirect_uri VARCHAR(2048),
    scopes TEXT[],
    code_challenge VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(10) NOT NULL,
    nonce VARCHAR(255),
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    family_id VARCHAR(255),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_oauth_authorizations_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_oauth_authorizations_challenge_method
        CHECK (code_challenge_method IN ('S256', 'plain'))
);

CREATE TABLE oauth_access_tokens (
    id BIGSERIAL PRIMARY KEY,
    token_id VARCHAR(255) NOT NULL UNIQUE,
    client_id BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    family_id VARCHAR(255),
    scopes TEXT[],
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE oauth_refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    family_id VARCHAR(255) NOT NULL,
    sequence INT NOT NULL DEFAULT 0,
    client_id BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    scopes TEXT[],
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_oauth_refresh_tokens_family_sequence UNIQUE (family_id, sequence),
    CONSTRAINT ck_oauth_refresh_tokens_expiry CHECK (expires_at > created_at)
);

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES "user"(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    resource VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255),
    detail JSONB DEFAULT '{}'::jsonb,
    client_ip INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    err_code INT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE FUNCTION update_updated_at_column() RETURNS trigger
LANGUAGE plpgsql AS U&'BEGIN
    NEW.updated_at = NOW()\003B
    RETURN NEW\003B
END\003B';

CREATE FUNCTION check_other_mail_limit() RETURNS trigger
LANGUAGE plpgsql AS U&'DECLARE
    mail_count INT\003B
BEGIN
    IF NEW.provider = ''other_mail'' THEN
        SELECT COUNT(*) INTO mail_count
        FROM identities
        WHERE user_id = NEW.user_id AND provider = ''other_mail''\003B
        IF mail_count >= 2 THEN
            RAISE EXCEPTION ''Each user can bind at most 2 additional emails.''\003B
        END IF\003B
    END IF\003B
    RETURN NEW\003B
END\003B';

CREATE FUNCTION auto_set_email_type() RETURNS trigger
LANGUAGE plpgsql AS U&'BEGIN
    IF LOWER(NEW.login_email) LIKE ''%@sast.fun'' THEN
        NEW.email_type := ''sast_email''\003B
    ELSIF LOWER(NEW.login_email) LIKE ''%@njupt.edu.cn'' THEN
        NEW.email_type := ''njupt_email''\003B
    ELSE
        RAISE EXCEPTION ''Invalid email domain: %. Only @njupt.edu.cn and @sast.fun are allowed.'', NEW.login_email\003B
    END IF\003B
    RETURN NEW\003B
END\003B';

CREATE INDEX idx_identities_user_id ON identities(user_id);
CREATE INDEX idx_identities_provider ON identities(provider);
CREATE UNIQUE INDEX uq_identities_user_github
    ON identities(user_id, provider) WHERE provider = 'github';
CREATE UNIQUE INDEX uq_identities_user_lark
    ON identities(user_id, provider) WHERE provider = 'lark';
CREATE INDEX idx_oauth_authorizations_expires_at
    ON oauth_authorizations(expires_at) WHERE is_used = FALSE;
CREATE INDEX idx_oauth_authorizations_client_id ON oauth_authorizations(client_id);
CREATE INDEX idx_oauth_authorizations_user_client ON oauth_authorizations(user_id, client_id);
CREATE INDEX idx_oauth_access_tokens_expires_at ON oauth_access_tokens(expires_at);
CREATE INDEX idx_oauth_access_tokens_user_id ON oauth_access_tokens(user_id);
CREATE INDEX idx_oauth_access_tokens_client_id ON oauth_access_tokens(client_id);
CREATE INDEX idx_oauth_access_tokens_family_id ON oauth_access_tokens(family_id);
CREATE INDEX idx_oauth_refresh_tokens_family_id ON oauth_refresh_tokens(family_id);
CREATE INDEX idx_oauth_refresh_tokens_user_id ON oauth_refresh_tokens(user_id);
CREATE INDEX idx_oauth_refresh_tokens_client_id ON oauth_refresh_tokens(client_id);
CREATE INDEX idx_oauth_refresh_tokens_expires_at
    ON oauth_refresh_tokens(expires_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX idx_audit_logs_user_created ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_action_created ON audit_logs(action, created_at DESC);

CREATE TRIGGER trg_user_updated_at
    BEFORE UPDATE ON "user" FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER trg_profile_updated_at
    BEFORE UPDATE ON profile FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER trg_identities_updated_at
    BEFORE UPDATE ON identities FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER trg_oauth_clients_updated_at
    BEFORE UPDATE ON oauth_clients FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER trg_identities_other_mail_limit
    BEFORE INSERT ON identities FOR EACH ROW EXECUTE FUNCTION check_other_mail_limit();
CREATE TRIGGER trg_user_email_domain
    BEFORE INSERT OR UPDATE OF login_email ON "user" FOR EACH ROW EXECUTE FUNCTION auto_set_email_type();
