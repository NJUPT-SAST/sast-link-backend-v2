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

-- 客户端类型（凭证能力，非信任级别）
CREATE TYPE client_enum AS ENUM (
    'first_party', -- 公开客户端：不生成 client_secret，token 端点仅凭 PKCE 认证
    'third_party' -- 机密客户端：持有 client_secret，token 端点双重认证（client_secret + PKCE）
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
    id            BIGSERIAL       PRIMARY KEY,
    role          user_role_enum  NOT NULL DEFAULT 'freshman',
    name          VARCHAR(255)    NOT NULL,
    phone_number  VARCHAR(20)     NOT NULL,
    qq_number     VARCHAR(20)     NOT NULL,
    password      VARCHAR(512)    NOT NULL,
    student_id    VARCHAR(50)     NOT NULL UNIQUE,
    state         state_enum      NOT NULL DEFAULT 'njupter',
    email_type    email_enum      NOT NULL,
    login_email   VARCHAR(255)    NOT NULL UNIQUE,
    created_at    TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    college       college_enum    NOT NULL DEFAULT '其他',
    major         VARCHAR(50)     NOT NULL DEFAULT '',
    token_version INT             NOT NULL DEFAULT 0
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
|`github`|`{"login": "github_username"}`|OAuth 流程：<https://docs.github.com/zh/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps>|
|`lark`|见下方示例|获取用户信息：<https://open.feishu.cn/document/server-docs/authentication-management/login-state-management/get><br><br>**provider_id 存储 `union_id`**（非 `open_id`）。`union_id` 在同一租户下跨应用一致，`open_id` 按应用变化，仅作为 identity_data 的一部分存储。|
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
    -- V007
    actor_client_id VARCHAR(255),
    created_at TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);
```

|字段名|说明|
|---|---|
|`id`||
|`user_id`|删除用户后保留日志|
|`action`|操作类型：register / login / logout / change_password / reset_password / oauth_bind / oauth_unbind / update_profile / upload_avatar / admin_user_update / admin_user_delete / admin_user_restore / admin_oauth_client_create / admin_oauth_client_update / admin_oauth_client_rotate_secret / oauth_authorize / oauth_token / oauth_revoke|
|`resource`|操作对象类型|
|`resource_id`|操作对象 ID|
|`detail`|JSONB 详情，各 action 结构见下文|
|`client_ip`|客户端 IP|
|`user_agent`|User-Agent|
|`success`|是否成功|
|`err_code`|错误码|
|`actor_client_id`|执行操作的 OAuth 客户端（行为主体，非被操作对象）。详见下方说明|
|`created_at`||

**`actor_client_id`（V007）**：记录**执行**该操作的 OAuth 客户端，与 `resource_id`（被操作对象）区分。控制台操作显式记录内置客户端 id（`sast-link-web`）而非 NULL，委派调用记录该第三方客户端的 `client_id`，两者据此可区分「管理员亲自操作」与「工具代其操作」；`/user` 自助面同理会话记内置客户端 id、`user:*` 第三方 token 记其 `azp`，区分「用户经控制台操作」与「应用代用户操作」。

NULL 是有意义的取值：**没有任何 OAuth 凭证授权该操作** —— 未认证流程（登录、注册、重置密码）、后台任务，以及 V007 之前写入的历史行。控制台之所以写显式值而非 NULL，正是为了让 NULL 只有这一层含义；历史行的歧义随 90 天保留期自行消失，无需回填。

刻意**无外键**：审计行必须比它命名的注册活得更久。`ON DELETE SET NULL` 会在注销客户端时把历史悄悄改写成「无凭证」，`RESTRICT` 则会让注销客户端卡在自己的审计尾巴上。同样**未加索引**：基数目前约为 1（仅一个委派客户端），既有 `action` 索引已把常用过滤切得足够小，且表有 90 天上限——等该过滤真有量再按 `EXPLAIN` 决定。

命名不用 `client_id`：本表已在两个不同角色上承载客户端标识——`resource_id` 在 `admin_oauth_client_*` 动作中存的是 oauth_client 主键，`detail` 在 OAuth token 端点中带 `client_id`。裸 `client_id` 在此处会真正产生「行为主体 vs 被操作对象」的歧义。

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
| 用户管理（`admin_user_update` / `admin_user_delete` / `admin_user_restore`） | `{"target_user_id": 123, ...}` |
| 客户端注册（`admin_oauth_client_create`） | `{"client_name": "string", "client_type": "third_party", "admin_scope": true}`（`admin_scope` / `user_scope` 仅在提交含对应能力 scope 时出现） |
| 客户端更新（`admin_oauth_client_update`） | `{"changed_fields": [...], "is_active": bool, "revoked_tokens": 3, "admin_scope_granted": ["admin:write"], "admin_scope_revoked": true, "user_scope_granted": ["user:read"], "user_scope_revoked": true, "scopes_removed": [...]}`（能力字段按发生情况出现） |

> **历史兼容**：dump 中现有 `audit_logs` 数据为 V1 people_link 迁移产物，detail 格式为
> `{"source": "people_link_merge", "action_type": "migration", "migrated_at": "...", "needs_password_reset": false}`。
> 此格式仅在迁移数据中存在，新系统不生成此格式。

**数据保留**：audit_logs 默认保留 90 天，可调大或收紧至最低 30 天，由 retention worker 清理过期数据（见[定时清理](#定时清理)）。

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
|`client_secret`|密钥 hash（SHA-256，`sha256-v1$` 版本前缀；非 argon2id/bcrypt，理由见 PRD §4.10）。NULL 表示公开客户端，当前即 `first_party`|
|`client_name`|应用名称|
|`client_type`|第一方应用 / 第三方应用|
|`redirect_uris`|允许的重定向 URI 列表|
|`grant_types`|authorization_code / refresh_token|
|`scopes`|授权范围|
|`is_active`|客户端是否被禁用|
|`created_at`||
|`updated_at`||

### 迁移种入的客户端

只有 `sast-link-web` 由迁移种入，因为服务本身依赖它存在（内部 API 的 `azp` 门钉死在这个 `client_id` 上）。其余客户端——包括持有 admin scope 的委派管理客户端——一律经控制台注册（见 API 文档 §6.5 / §6.7），迁移不再种入任何接入方客户端。

|`client_id`|迁移|类型|scopes|grant_types|用途|
|---|---|---|---|---|---|
|`sast-link-web`|V003|`first_party`（无 secret）|`openid` `profile` `email`|`authorization_code` `refresh_token`|内置控制台。内部 API 通过 `azp` 钉死在此客户端上；停用它是不可自行恢复的锁死（登录/刷新/注册均经由它解析，且同一操作会撤销全部内部会话 token），故控制台接口拒绝停用、改写其 `redirect_uris`、修改其 `scopes` 与 `grant_types`（`grant_types` 由 V003 种子值钉死，控制台自身的 OAuth 会话经 refresh grant 续期）|

**为什么接入方客户端不走迁移**：`client_secret` 是需要轮换的凭证，而 seed 迁移必须带漂移检测（既有行属性不符则中止，否则重复 apply 会覆盖一个存活客户端的 scope 或回调地址）。两者不相容——凭证一经轮换，库里的哈希就不再等于迁移里写死的那个，任何需要重跑该迁移的路径（`down` 后再 `up`、灾备重建、从生产 dump 恢复后跑迁移）都会中止且无法绕过。把 secret 从漂移检测中排除也不成立：那样 `down`/`up` 会把轮换后的行删掉并重建成迁移里的旧 secret，等于让一个已作废的凭证重新生效。

一个接入方（如 SAST People，注册为 `third_party` 机密客户端）用一个客户端即可承载全部能力：`{openid profile email user:* admin:*}` + refresh。普通用户经它自助读/改自己的资料，admin 角色用户经它查人/改角色/封禁——能力由 `/admin` 的角色门按 token 主体区分，无需拆客户端。二者共用同一组 `redirect_uris`：`authorize` 校验的是「该 URI 在**这个** client 的注册列表内」，不要求全局唯一。

若接入方需要让用户自助读/改资料（SAST People 即此例），客户端再加 `user:read` / `user:write`（**无客户端类型约束**，任何客户端可持有，允许 refresh，见 PRD §4.13 用户自助面）即可访问 `/user/*` 读/改当前用户完整资料——无需经 `/admin/*`，`/userinfo` 的 OIDC 视图也不再是唯一选项。

管理能力（`admin:*`）必须由 `third_party` 机密客户端持有，因为 `first_party` 是公开客户端、token 端点仅凭 PKCE 认证它。scope 本身对两类客户端一律受 `ContainsAll` 约束。控制台授予 admin scope 受三道守卫约束（必须 `third_party`、只能由内置控制台客户端发起、不得与改写 `redirect_uris` 同请求），且判定基于合并后状态以防拆包绕过；admin scope 允许 `refresh_token`——`/admin` 的角色门从数据库行读取主体角色，刷新不会拓宽谁能用它。收窄 scope 或新授予能力 scope 都会连带撤销该客户端存量 token。`client_secret` 只以 `sha256-v1$...` 哈希入库，明文仅在注册响应与 secret 轮换响应中出现一次。

V003 是幂等的：重复 apply 为 no-op，带漂移检测（既有行属性不符则 `RAISE EXCEPTION` 中止而非覆盖），并把自己创建的行记入 ownership 表，使 `down` 只删自己建的且未被任何授权码/token 引用过的行。它的 `client_secret` 为 NULL，因此不受上述凭证轮换问题影响。

## oauth_authorizations 授权码

Authorization Code + PKCE 流程中的短期授权码。一次性使用，过期后定时任务清理。

> 协议层要求 PKCE S256-only。V001 历史迁移中的 `ck_oauth_authorizations_challenge_method` 仍允许 `plain`，用于保留已发布 schema 的真实状态；V002 迁移已将该约束收紧为仅允许 `S256`。

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
        CHECK (code_challenge_method IN ('S256', 'plain'))  -- V002 replaces this with = 'S256'
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
|`code_challenge_method`|V001 历史约束允许 `S256` 或 `plain`；协议层 S256-only，V002 收紧为仅 `S256`|
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

> 此表无 `updated_at`。生命周期为"创建 → 标记已用"。已使用 + 已过期的 code 由 API 内 retention worker 统一清理；V006 增设全量 `expires_at` 索引 `idx_oauth_authorizations_expires_at_all`，过期行按索引定位，无需 seq scan

## oauth_access_tokens 元数据

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

-- V008 未撤销且已过期：retention 清理死族分支（含从未旋转的 sequence-0 行）的外层 expires_at 谓词。
-- V001 的部分索引恰好排除 revoked_at IS NULL 的行，若无此索引该分支退化为全表扫描
CREATE INDEX idx_oauth_refresh_tokens_expires_at_live
    ON oauth_refresh_tokens(expires_at)
    WHERE revoked_at IS NULL;
```

> 此表无 `updated_at`。Token 旋转 = INSERT 新行 + UPDATE `revoked_at`。

## token_blacklist_outbox 令牌黑名单投递箱

持久化投递箱（Outbox）模式，用于 JWT 撤销的可靠投递。当在 PostgreSQL 事务中调用 `RevokeFamily` 时，每一条仍在有效期内的 JWT `jti` 会被 UPSERT 到此表。后台 worker 认领所有投递行，失效对应 auth-state 缓存条目并在成功后确认删除，因此同步失效失败与并发 refresh replay 产生的撤销都会最终重试。失败的投递保留在表中，按指数退避重试。行在其 JWT 生存期过后自然过期。

```sql
CREATE TABLE token_blacklist_outbox (
    id              BIGSERIAL        PRIMARY KEY,
    token_id        VARCHAR(255)     NOT NULL UNIQUE,
    expires_at      TIMESTAMPTZ      NOT NULL,
    next_delivery_at TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempt_count   INTEGER          NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    last_error      TEXT,
    claim_token     VARCHAR(64),
    claimed_until   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ      NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

| 字段名 | 说明 |
|--------|------|
| `id` | 主键 |
| `token_id` | JWT `jti` 值，唯一约束，同一 JTI 重复 UPSERT 不产生重复行 |
| `expires_at` | JWT 本身的过期时间。超过此时间后该行不再需要投递（JWT 已自然失效） |
| `next_delivery_at` | 下次投递时间。首次插入为当前时间，重试时按指数退避递增 |
| `attempt_count` | 已尝试投递次数，用于计算退避间隔 |
| `last_attempt_at` | 最近一次投递尝试时间 |
| `last_error` | 最近一次失败的错误信息，用于诊断 |
| `claim_token` | Worker 认领令牌。NULL 表示未被认领，非 NULL 表示已被某 worker 持有 |
| `claimed_until` | 认领租约过期时间。超过此时间后其他 worker 可重新认领 |
| `created_at` | 行创建时间 |

```sql
-- 待发送记录按 next_delivery_at 顺序取，跳过已被其他 worker 认领的行
CREATE INDEX idx_token_blacklist_outbox_due
    ON token_blacklist_outbox (next_delivery_at, expires_at, id)
    WHERE claim_token IS NULL;

-- 已认领但租约到期的行可以被重新认领
CREATE INDEX idx_token_blacklist_outbox_claimed_until
    ON token_blacklist_outbox (claimed_until)
    WHERE claim_token IS NOT NULL;

-- 清理已自然过期的记录（每条 JTI 在其 JWT 过期后无需继续投递）
CREATE INDEX idx_token_blacklist_outbox_expiry
    ON token_blacklist_outbox (expires_at);
```

> 此表无 `updated_at`。生命周期为"UPSERT → 认领 → 投递成功 DELETE / 过期清理"。`claim_token` + `claimed_until` 实现分布式 worker 的乐观锁认领，避免重复投递。

### Worker 认领与投递流程

```text
-- 1. Worker 认领到期行（原子操作，跳过已被认领且租约未到期的行）
UPDATE token_blacklist_outbox
SET claim_token   = $worker_token,
    claimed_until = NOW() + INTERVAL '30 seconds'
WHERE id IN (
    SELECT id FROM token_blacklist_outbox
    WHERE (claim_token IS NULL OR claimed_until < NOW())
      AND next_delivery_at <= NOW()
      AND expires_at > NOW()
    ORDER BY next_delivery_at, id
    LIMIT $batch_size
    FOR UPDATE SKIP LOCKED
)
RETURNING *;

-- 2. 失效对应 auth-state 缓存条目（DeleteAuthStates）

-- 3. 成功 → DELETE FROM token_blacklist_outbox WHERE id = $id;
--    失败 → UPDATE token_blacklist_outbox
--           SET next_delivery_at = NOW() + (2 ^ LEAST(attempt_count, 10)) * INTERVAL '1 second',
--               attempt_count   = attempt_count + 1,
--               last_attempt_at = NOW(),
--               last_error      = $error,
--               claim_token     = NULL,
--               claimed_until   = NULL
--           WHERE id = $id;
```

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
>
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

> `oauth_authorizations`、`oauth_access_tokens`、`oauth_refresh_tokens`、`token_blacklist_outbox`、`audit_logs` 无 `updated_at`，不需要自动更新触发器。
>
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

清理由 API 进程内的 Go worker（`internal/worker/retention.go`）按 ticker 执行，**不使用
`pg_cron`**。

#### 为什么不用 pg_cron

- 生产库没有安装该扩展，安装需要改 `shared_preload_libraries` 并重启数据库。
- 更关键的是可测性：集成测试用 `postgres:16-alpine`，该镜像根本无法加载 pg_cron，
  走 pg_cron 意味着这部分清理规则在 CI 中永远没有测试覆盖。
- 项目已有同类先例：`internal/service/session/worker/token_blacklist.go` 早已在 Go 侧
  每小时清理 `token_blacklist_outbox`。因此这里沿用既有模式，而非引入第二套调度机制。

代价是清理只在 API 进程存活期间发生。服务全停时不清理，但此时也没有新数据写入，
不影响正确性。

#### 多实例协调

每轮 sweep 前用 `pg_try_advisory_lock` 抢锁，抢不到就跳过本轮（而非排队等待）——清理
错过一轮无害，下一轮覆盖同样的行。所有删除都是 `DELETE WHERE 已死`，天然幂等，锁只是
避免多实例重复扫描。

该锁是 session 级的，而 GORM 连接池每条语句可能取到不同连接，因此 `TryLock` 会固定
（pin）一条连接，`Unlock` 在同一条连接上释放后再归还。否则 `pg_advisory_unlock` 可能
跑在从未持锁的连接上——它只返回 false 而不报错，真正的持锁连接会一直锁到被回收，
阻塞此后所有实例的每一轮 sweep。

#### 清理策略说明

窗口均为「从现在往前推」，即行必须已死满整个窗口才删除，余量用于吸收 API 与数据库之间
的时钟偏差。全部可通过环境变量调整，见 `.env.example` 的 `RETENTION_*`。

| 表 | 清理对象 | 默认窗口 | 说明 |
|----|---------|---------|------|
| `oauth_authorizations` | 已过期，无论是否使用 | `expires_at` + 1h | 授权码单次使用，重放由兑换时的 family 撤销处理，过期行不再承载任何权限。V001 的 `idx_oauth_authorizations_expires_at` 是部分索引（`WHERE is_used = FALSE`），而已兑换才是常态，故 **V006 增设全量索引** `idx_oauth_authorizations_expires_at_all`，否则每小时退化为全表扫描 |
| `oauth_access_tokens` | 已过期元数据 | `expires_at` + 24h | 远宽于默认 1h 的 access token TTL，且校验拒绝小于 `JWT_ACCESS_TOKEN_EXPIRY` 的配置。原因：中间件对「JTI 不存在」与「已撤销」返回同一个 401，若在 JWT 仍处于 `exp` 内时删掉元数据，仅仅过期的 token 会被呈现为已撤销——客户端读到的是被强制登出，而不是该去刷新。JWT 校验器没有 leeway 可依赖，这些行又很小，窗口宽一点很便宜 |
| `oauth_refresh_tokens` | 已撤销且 `sequence > 0`；或整个 family 已死（无任何未撤销且未过期的成员） | `expires_at` + 24h | 两个分支：轮换掉的行（`revoked_at` 已设）由 V001 的部分索引服务；死族分支还包括从未旋转的 sequence-0 行（`revoked_at IS NULL`），其外层 `expires_at` 谓词由 **V008** 的 `idx_oauth_refresh_tokens_expires_at_live` 服务，族内探测用 `family_id` 索引。**必须保留每个存活 family 的 sequence-0 行**：`FindFamilyOriginCreatedAt` 靠它给 ID Token 的 `auth_time` 定时间，而该行从首次轮换起就带有 `revoked_at`。只要 family 还在轮换，它会活得比自己的 `expires_at` 更久；删掉会让刷新流程撤销整个 family 并返回 500——即用户被强制登出。每个 family 长期留一行，是换取 `auth_time` 准确的成本 |
| `audit_logs` | 超过保留期 | `created_at` + 90d | 90 天（PRD §9）是**默认值**：审计日志在这里属运维用途而非合规强制，可调大以保留更多历史，也可收紧至 30 天下限；低于下限启动时拒绝，避免误配到「事故排查时相关记录已被删」的程度 |

`token_blacklist_outbox` 不在此列：`sessionworker.TokenBlacklist` 已负责清理它，再加一个
清理者只会让两者竞争同一张表。

单条语句删除的行数受 `RETENTION_BATCH_SIZE` 限制，扫到满批就继续下一批，直到某批不满为止；
单轮最多 20 批，剩余积压留给下一轮，避免长期未清理的表占用在线流量所需的连接池份额。

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

10. `token_blacklist_outbox` 表（无 FK，独立表）

11. `audit_logs` 表（FK → user）

12. 所有索引

13. 所有触发器

14. 索引/触发器复核（清理由 API 内 retention worker 执行，不使用 pg_cron）
