# 数据库表结构设计

## 枚举类型

```sql
-- 用户角色
CREATE TYPE user_role_enum AS ENUM (
    'freshman',   -- 大一新生
    'member',     -- 正式成员（大一过 woc/soc/面试）
    'lecturer',   -- 讲师
    'admin'       -- 管理员
);

-- 部门
CREATE TYPE department_enum AS ENUM (
    'software',   -- 软件部
    'media'       -- 媒体部
);

-- 第三方登录方式
CREATE TYPE login_method_enum AS ENUM (
    'github',     -- GitHub OAuth
    'lark',       -- 飞书 OAuth
    'other_mail'  -- 其他邮箱绑定
);

-- 用户状态（状态机）
CREATE TYPE state_enum AS ENUM (
    'is_deleted',     -- 账号已注销
    'on_sast',        -- 现任 SAST 成员
    'retired_sast',   -- 已毕业 / 已离开 SAST
    'njupter'         -- NJUPT 在校生，尚未加入 SAST（招新阶段）
);

-- 注册邮箱类型
CREATE TYPE email_enum AS ENUM (
    'sast_email',   -- @sast.fun（校友邮箱）
    'njupt_email'   -- @njupt.edu.cn（在校生邮箱）
);

-- 客户端类型
CREATE TYPE client_enum AS ENUM (
    'first_party', -- sast 内部应用，受信任的
    'third_party' -- 外部接入应用，需走OAuth流程
);

-- 学院
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
```

## user 用户表

```sql
CREATE TABLE "user" (
    id           BIGSERIAL       PRIMARY KEY,
    role         user_role_enum  NOT NULL DEFAULT 'freshman',
    name         VARCHAR(255)    NOT NULL,
    phone_number VARCHAR(20)     NOT NULL,
    qq_number    VARCHAR(20)     NOT NULL,
    password     VARCHAR(512)    NOT NULL,
    token_version INT             NOT NULL DEFAULT 0,
    student_id   VARCHAR(50)     UNIQUE,
    state        state_enum      NOT NULL DEFAULT 'njupter',
    email_type   email_enum      NOT NULL,
    login_email        VARCHAR(255)    NOT NULL UNIQUE,
    created_at   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    college       college_enum    NOT NULL DEFAULT '其他',
    major         varchar(50)     NOT NULL DEFAULT ''
);
```

|**字段名**|**说明**|
|---|---|
|id|主键，系统内部用户标识|
|role|enum { 'freshman','member','lecturer','admin'}|
|name|姓名|
|phone_number|手机号|
|qq_number|QQ 号|
|password|密码，不可为空|
|token_version|Token 版本号，改密/重置密码后递增，JWT 校验时比对，不匹配则拒绝|
|student_id|学号|
|state|enum {'is_deleted','on_sast','retired_sast','njupter'}|
|email_type|注册邮箱类型，见 `email_enum`|
|login_email|注册邮箱|
|created_at|创建时间|
|updated_at|最后更新时间|
|college|学院，见 `college_enum`|
|major|专业|

## Profile 用户信息表

```sql
CREATE TABLE profile (
    id          BIGSERIAL        PRIMARY KEY,
    user_id     BIGINT           NOT NULL UNIQUE
                                 REFERENCES "user"(id) ON DELETE CASCADE,
    nickname    VARCHAR(255),
    department  department_enum,
    intro       VARCHAR(255),
    email       VARCHAR(255),
    avatar      VARCHAR(512),
    blog_url    VARCHAR(512),
    github_url  VARCHAR(512),
    created_at  TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);
```

|**字段名**|**说明**|
|---|---|
|id|主键|
|user_id|一对一关联 user 表|
|nickname|昵称|
|department|enum {'software','media'}（可用于权限隔离）|
|intro|自我介绍|
|email|对外展示邮箱|
|avatar|头像url|
|blog_url|个人博客|
|github_url|GitHub主页链接|
|created_at|首次创建时间|
|updated_at|最后更新时间|

## identities 表 第三方账号绑定

```sql
CREATE TABLE identities (
    id                BIGSERIAL        PRIMARY KEY,
    user_id           BIGINT           NOT NULL
                                       REFERENCES "user"(id) ON DELETE CASCADE,
    provider          login_method_enum NOT NULL,
    provider_id       VARCHAR(255)     NOT NULL,
    identity_data     JSONB,
    access_token      TEXT,
    refresh_token     TEXT,
    token_expires_at  TIMESTAMPTZ,
    created_at        TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

    -- 同一第三方账号只能绑定一个用户
    CONSTRAINT uq_identities_provider_provider_id
        UNIQUE (provider, provider_id)
);

-- github 和 lark：每用户仅一条
CREATE UNIQUE INDEX uq_identities_user_github
    ON identities(user_id, provider) WHERE provider = 'github';

CREATE UNIQUE INDEX uq_identities_user_lark
    ON identities(user_id, provider) WHERE provider = 'lark';
```

|字段名|说明|
|---|---|
|`id`|主键|
|`user_id`|关联的 SAST 用户|
|`provider`|绑定类型：github / lark / other_mail|
|`provider_id`|第三方唯一 ID（GitHub ID / 飞书 union_id / 绑定的邮箱地址）|
|`identity_data`|第三方平台资料，Schema 见下方|
|`access_token`|第三方 OAuth 访问令牌|
|`refresh_token`|第三方 OAuth 刷新令牌|
|`token_expires_at`|第三方 access_token 过期时间|
|`created_at`|绑定创建时间|
|`updated_at`|绑定信息最后更新时间|

identity_data JSON 结构

|Provider|JSON 结构|说明|
|---|---|---|
|`github`|`{"login": "github_username"}`|OAuth 流程：https://docs.github.com/zh/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps|
|`lark`|见下方示例|获取用户信息：https://open.feishu.cn/document/server-docs/authentication-management/login-state-management/get<br><br>**provider_id 存储 `union_id`**（非 `open_id`）。`union_id` 在同一租户下跨应用一致，`open_id` 按应用变化，仅作为 identity_data 的一部分存储。|
|`other_mail`|`{"email": "xxx@example.com"}`|额外绑定邮箱，`provider_id` 同时存该邮箱地址。每行一条，最多 2 行|

`lark` 示例（存储飞书 API 返回的 `data` 对象，不含外层 `code`/`msg` 包）：

```json
{
  "name": "zhangsan",
  "en_name": "zhangsan",
  "avatar_url": "www.feishu.cn/avatar/icon",
  "avatar_thumb": "www.feishu.cn/avatar/icon_thumb",
  "avatar_middle": "www.feishu.cn/avatar/icon_middle",
  "avatar_big": "www.feishu.cn/avatar/icon_big",
  "open_id": "ou-caecc734c2e3328a62489fe0648c4b98779515d3",
  "union_id": "on-d89jhsdhjsajkda7828enjdj328ydhhw3u43yjhdj",
  "email": "zhangsan@feishu.cn",
  "enterprise_email": "demo@mail.com",
  "user_id": "5d9bdxxx",
  "mobile": "+86130002883xx",
  "tenant_key": "736588c92lxf175d",
  "employee_no": "111222333"
}
```

```sql
-- 外键索引
CREATE INDEX idx_identities_user_id ON identities(user_id);

-- 按 provider 查询索引
CREATE INDEX idx_identities_provider ON identities(provider);
```

## audit_logs 操作日志表

```sql
CREATE TABLE audit_logs (
    id         BIGSERIAL        PRIMARY KEY,
    user_id    BIGINT           REFERENCES "user"(id) ON DELETE SET NULL,
    action     VARCHAR(50)      NOT NULL,
    resource   VARCHAR(50)      NOT NULL,
    resource_id VARCHAR(255),
    detail     JSONB            DEFAULT '{}'::jsonb,
    client_ip  INET,
    user_agent TEXT,
    success    BOOLEAN          NOT NULL DEFAULT TRUE,
    err_code   INT,
    created_at TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);
```

|字段名|说明|
|---|---|
|`id`||
|`user_id`|删除用户后保留日志|
|`action`|操作类型：register / login / logout / change_password / reset_password / oauth_bind / oauth_unbind / update_profile / upload_avatar / admin_action|
|`resource`|操作对象类型|
|`resource_id`|操作对象 ID|
|`detail`|JSONB 详情，各 action 结构见下文|
|`client_ip`|客户端 IP|
|`user_agent`|User-Agent|
|`success`|是否成功|
|`err_code`|错误码|
|`created_at`||

**detail JSONB 结构**（按 action）：

| action | 字段 |
|--------|------|
| `register` | `{"login_email": "string"}` |
| `login` | `{"method": "password" \| "github" \| "lark" \| "other_mail"}` |
| `logout` | `{}` |
| `change_password` | `{}` |
| `reset_password` | `{}` |
| `oauth_bind` | `{"provider": "github" \| "lark" \| "other_mail", "provider_id": "string"}` |
| `oauth_unbind` | `{"provider": "github" \| "lark" \| "other_mail", "provider_id": "string"}` |
| `update_profile` | `{"changed_fields": ["field1", "field2", ...]}` |
| `upload_avatar` | `{"avatar_url": "string"}` |
| `admin_action` | `{"target_user_id": 123, "sub_action": "edit_user" \| "delete_user" \| "restore_user" \| "manage_oauth_client"}` |

**数据保留**：audit_logs 保留 90 天，通过 pg_cron 每天清理过期数据（见[定时清理](#定时清理)）。

```sql
CREATE INDEX idx_audit_logs_user_created ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_action_created ON audit_logs(action, created_at DESC);
```

## oauth_clients 客户端注册表

```sql
CREATE TABLE oauth_clients (
    id              BIGSERIAL        PRIMARY KEY,
    client_id       VARCHAR(255)     NOT NULL UNIQUE,
    client_secret   VARCHAR(255),    -- NULLable：第一方应用存 NULL
    client_name     VARCHAR(255)     NOT NULL,
    client_type     client_enum      NOT NULL,
    redirect_uris   TEXT[]           NOT NULL,
    grant_types     TEXT[]           NOT NULL,
    scopes          TEXT[]           NOT NULL DEFAULT '{}'::text[],
    is_active       BOOLEAN          NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_oauth_clients_redirect_uris
        CHECK (COALESCE(array_length(redirect_uris, 1), 0) > 0),
    CONSTRAINT ck_oauth_clients_grant_types
        CHECK (COALESCE(array_length(grant_types, 1), 0) > 0)
);
```

|字段名|说明|
|---|---|
|`id`|内部主键|
|`client_id`|公开客户端标识符（随机字符串）|
|`client_secret`|密钥 hash（bcrypt）。第一方应用存 NULL|
|`client_name`|应用名称|
|`client_type`|第一方应用 / 第三方应用|
|`redirect_uris`|允许的重定向 URI 列表|
|`grant_types`|authorization_code / refresh_token|
|`scopes`|授权范围|
|`is_active`|客户端是否被禁用|
|`created_at`||
|`updated_at`||

## oauth_authorizations 授权码

Authorization Code + PKCE 流程中的短期授权码。一次性使用，过期后定时任务清理

```sql
CREATE TABLE oauth_authorizations (
    id                    BIGSERIAL        PRIMARY KEY,
    code                  VARCHAR(255)     NOT NULL UNIQUE,
    client_id             BIGINT           NOT NULL
                                           REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id               BIGINT           NOT NULL
                                           REFERENCES "user"(id) ON DELETE CASCADE,
    redirect_uri          VARCHAR(2048),
    scopes                TEXT[],
    code_challenge        VARCHAR(255)    NOT NULL,
    code_challenge_method VARCHAR(10)     NOT NULL,
    nonce                 VARCHAR(255),
    is_used               BOOLEAN          NOT NULL DEFAULT FALSE,
    family_id             VARCHAR(255),
    expires_at            TIMESTAMPTZ      NOT NULL,
    created_at            TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_oauth_authorizations_expiry
        CHECK (expires_at > created_at),
    CONSTRAINT ck_oauth_authorizations_challenge_method
        CHECK (code_challenge_method IN ('S256', 'plain'))
);
```

|字段名|说明|
|---|---|
|`id`||
|`code`|授权码|
|`client_id`||
|`user_id`||
|`redirect_uri`|授权请求时的 redirect_uri|
|`scopes`|请求范围|
|`code_challenge`|PKCE code_challenge 值|
|`code_challenge_method`|`S256` 或 `plain`|
|`nonce`|OIDC nonce|
|`is_used`|是否已使用|
|`family_id`|Token Family UUID。code 被重放时，通过此字段级联撤销整条 token 链|
|`expires_at`|过期时间（5-10 分钟）|
|`created_at`||

```sql
CREATE INDEX idx_oauth_authorizations_expires_at
    ON oauth_authorizations(expires_at)
    WHERE is_used = FALSE;

CREATE INDEX idx_oauth_authorizations_client_id
    ON oauth_authorizations(client_id);
CREATE INDEX idx_oauth_authorizations_user_client
    ON oauth_authorizations(user_id, client_id);
```

> 此表无 `updated_at`。生命周期为"创建 → 标记已用"。

## **oauth_access_tokens 元数据**

JWT Access Token 为自包含，服务端存储元数据用于撤销追踪与审计

```sql
CREATE TABLE oauth_access_tokens (
    id         BIGSERIAL        PRIMARY KEY,
    token_id   VARCHAR(255)     NOT NULL UNIQUE,
    client_id  BIGINT           NOT NULL
                                REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id    BIGINT           NOT NULL
                                REFERENCES "user"(id) ON DELETE CASCADE,
    family_id  VARCHAR(255),
    scopes      TEXT[],
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ      NOT NULL,
    created_at TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);
```

|字段名|说明|
|---|---|
|`id`||
|`token_id`|JWT jti|
|`client_id`||
|`user_id`||
|`family_id`|Token Family UUID，级联撤销时定位该链所有 token|
|`scopes`|授权范围|
|`revoked_at`|撤销时间，NULL = 未撤销|
|`expires_at`||
|`created_at`||

```sql
CREATE INDEX idx_oauth_access_tokens_expires_at
    ON oauth_access_tokens(expires_at);

CREATE INDEX idx_oauth_access_tokens_user_id
    ON oauth_access_tokens(user_id);

CREATE INDEX idx_oauth_access_tokens_client_id
    ON oauth_access_tokens(client_id);
    
CREATE INDEX idx_oauth_access_tokens_family_id
    ON oauth_access_tokens(family_id);
```

> 此表无 `updated_at`。创建后只读，撤销即 `UPDATE revoked_at = NOW()`。

## oauth_refresh_tokens Refresh Token 表

```sql
CREATE TABLE oauth_refresh_tokens (
    id         BIGSERIAL        PRIMARY KEY,
    token_hash VARCHAR(255)     NOT NULL UNIQUE,
    family_id  VARCHAR(255)     NOT NULL,
    sequence   INT              NOT NULL DEFAULT 0,
    client_id  BIGINT           NOT NULL
                                REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id    BIGINT           NOT NULL
                                REFERENCES "user"(id) ON DELETE CASCADE,
    scopes      TEXT[],
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ      NOT NULL,
    created_at TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_oauth_refresh_tokens_family_sequence
        UNIQUE (family_id, sequence),

    CONSTRAINT ck_oauth_refresh_tokens_expiry
        CHECK (expires_at > created_at)
);
```

|字段名|说明|
|---|---|
|`id`||
|`token_hash`|HMAC-SHA256(key, token) 存储|
|`family_id`|Token Family UUID|
|`sequence`|家族内序号，旋转递增|
|`client_id`||
|`user_id`||
|`scopes`|授权范围|
|`revoked_at`|NULL = 未撤销|
|`expires_at`||
|`created_at`||

```sql
-- 注：(family_id, sequence) UNIQUE 和 token_hash UNIQUE 由 PG 自动建唯一索引，下面仅为非唯一查询列补索引

CREATE INDEX idx_oauth_refresh_tokens_family_id
    ON oauth_refresh_tokens(family_id);

CREATE INDEX idx_oauth_refresh_tokens_user_id
    ON oauth_refresh_tokens(user_id);

CREATE INDEX idx_oauth_refresh_tokens_client_id
    ON oauth_refresh_tokens(client_id);

-- 已撤销且已过期
CREATE INDEX idx_oauth_refresh_tokens_expires_at
    ON oauth_refresh_tokens(expires_at)
    WHERE revoked_at IS NOT NULL;
```

> 此表无 `updated_at`。Token 旋转 = INSERT 新行 + UPDATE `revoked_at`。

## 函数、触发器与运维

### 函数

**update_updated_at_column**

```sql
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

**check_other_mail_limit**

> 已知限制：
> 1. 并发竞态：READ COMMITTED 下两个并发事务各自 COUNT 可能都为 1，同时放行，最终 >2 条。对于 SAST 内部系统规模可接受，`uq_identities_provider_provider_id` 至少能防完全重复行。
> 2. UPDATE 场景：触发器仅绑定 `BEFORE INSERT`，`UPDATE` 改 provider 为 `other_mail` 的场景由应用层兜底。

```sql
CREATE OR REPLACE FUNCTION check_other_mail_limit()
RETURNS TRIGGER AS $$
DECLARE
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
END;
$$ LANGUAGE plpgsql;
```

**auto_set_email_type**

> 邮箱域名决定 `email_type`。

```sql
CREATE OR REPLACE FUNCTION auto_set_email_type()
RETURNS TRIGGER AS $$
BEGIN
    IF LOWER(NEW.login_email) LIKE '%@sast.fun' THEN
        NEW.email_type := 'sast_email';
    ELSIF LOWER(NEW.login_email) LIKE '%@njupt.edu.cn' THEN
        NEW.email_type := 'njupt_email';
    ELSE
        RAISE EXCEPTION 'Invalid email domain: %. Only @njupt.edu.cn and @sast.fun are allowed.', NEW.login_email;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

---

### 触发器

```sql
-- updated_at 自动更新
CREATE TRIGGER trg_user_updated_at
    BEFORE UPDATE ON "user"
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_profile_updated_at
    BEFORE UPDATE ON profile
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_identities_updated_at
    BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_oauth_clients_updated_at
    BEFORE UPDATE ON oauth_clients
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- other_mail 数量上限
CREATE TRIGGER trg_identities_other_mail_limit
    BEFORE INSERT ON identities
    FOR EACH ROW EXECUTE FUNCTION check_other_mail_limit();

-- 邮箱域名自动检测
CREATE TRIGGER trg_user_email_domain
    BEFORE INSERT OR UPDATE OF login_email ON "user"
    FOR EACH ROW EXECUTE FUNCTION auto_set_email_type();
```

> `oauth_authorizations`、`oauth_access_tokens`、`oauth_refresh_tokens`、`audit_logs` 无 `updated_at`，不需要自动更新触发器。

> `check_other_mail_limit` 仅检查 INSERT（存在并发竞态，见函数注释）。UPDATE 改 provider 为 `other_mail` 的场景由应用层兜底。

---

### 级联撤销流程

code 被重放时，通过 `family_id` 全链斩断：

```text
SELECT family_id FROM oauth_authorizations WHERE code = $replayed_code;
UPDATE oauth_access_tokens  SET revoked_at = NOW() WHERE family_id = $family_id;
UPDATE oauth_refresh_tokens SET revoked_at = NOW() WHERE family_id = $family_id;
```

三表通过单一 `family_id` 串联：

```text
oauth_authorizations.family_id
  ├── oauth_access_tokens.family_id
  └── oauth_refresh_tokens.family_id
```

---

### 定时清理

使用 `pg_cron` 在 PostgreSQL 内部调度，无多实例重复执行问题。

#### 前置：安装扩展

```sql
CREATE EXTENSION IF NOT EXISTS pg_cron;
```

> 云托管 PG 通常已内置，本地/Docker 需 `shared_preload_libraries = 'pg_cron'` 并重启。

#### 清理任务调度

```sql
-- 每小时：清理已过期且未使用的授权码
SELECT cron.schedule(
    'cleanup-expired-authorizations',
    '0 * * * *',
    $$DELETE FROM oauth_authorizations WHERE expires_at < NOW() - INTERVAL '1 hour'$$
);

-- 每小时：清理已过期的 access_token 元数据
SELECT cron.schedule(
    'cleanup-expired-access-tokens',
    '0 * * * *',
    $$DELETE FROM oauth_access_tokens WHERE expires_at < NOW() - INTERVAL '1 hour'$$
);

-- 每天凌晨 3 点：清理已撤销且已过期的 refresh_token
SELECT cron.schedule(
    'cleanup-revoked-refresh-tokens',
    '0 3 * * *',
    $$DELETE FROM oauth_refresh_tokens WHERE revoked_at IS NOT NULL AND expires_at < NOW() - INTERVAL '1 day'$$
);

-- 每天凌晨 4 点：清理超过 90 天保留期的审计日志
SELECT cron.schedule(
    'cleanup-expired-audit-logs',
    '0 4 * * *',
    $$DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '90 days'$$
);
```

#### 管理命令

```sql
-- 查看所有定时任务
SELECT * FROM cron.job;

-- 暂停 / 恢复某个任务
SELECT cron.alter_job(<job_id>, active := false);
SELECT cron.alter_job(<job_id>, active := true);

-- 删除任务
SELECT cron.unschedule(<job_id>);
```

#### 清理策略说明

| 表 | 清理对象 | 频率 | 延迟窗口 |
|----|---------|------|---------|
| `oauth_authorizations` | 已过期，无论是否使用 | 每小时 | `expires_at` + 1h（留缓冲防时钟偏差） |
| `oauth_access_tokens` | 已过期元数据 | 每小时 | `expires_at` + 1h |
| `oauth_refresh_tokens` | 已撤销 **且** 已过期 | 每天 | `expires_at` + 1d（只清已撤销的，未撤销的 refresh_token 过期后仍可查审计） |
| `audit_logs` | 超过保留期数据 | 每天 | `created_at` + 90d（90 天保留期） |

---

### 建表顺序

1. 枚举类型（7 个 CREATE TYPE）

2. 三个工具函数

3. `"user"` 表

4. `oauth_clients` 表

5. `profile` 表（FK → user）

6. `identities` 表（FK → user）

7. `oauth_authorizations` 表（FK → oauth_clients, user）

8. `oauth_access_tokens` 表（FK → oauth_clients, user）

9. `oauth_refresh_tokens` 表（FK → oauth_clients, user）

10. `audit_logs` 表（FK → user）

11. 所有索引

12. 所有触发器

13. pg_cron 扩展 + 定时清理任务调度

