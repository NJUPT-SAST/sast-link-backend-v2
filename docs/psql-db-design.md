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
    '欧洲塞浦路斯学院', -- V012 新增
    '其他'
);

-- 校友建号申请状态（V011）
CREATE TYPE alumni_request_status_enum AS ENUM (
    'pending',    -- 待审
    'approved',   -- 已通过（已建号）
    'rejected'    -- 已驳回（不占待审名额，可修正后重新提交）
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
    token_version INT             NOT NULL DEFAULT 0,
    -- V010 新增，生成列（GENERATED ALWAYS AS ... STORED）
    profile_needs_completion BOOLEAN GENERATED ALWAYS AS (
        sl_profile_is_blank(name)
        OR sl_profile_is_blank(phone_number)
        OR sl_profile_is_blank(qq_number)
        OR sl_profile_is_blank(major)
        OR lower(btrim(name)) = lower(btrim(student_id))
    ) STORED
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
|profile_needs_completion|V010 生成列。旧库迁移账号的资料补全标志，详见下方说明|

### profile_needs_completion（V010）

旧数据库迁移过来的账号，部分必填字段带着当前写入路径不会接受的值：`name` / `phone_number` / `qq_number` / `major`
为空白，或 `name` 被填成了 `student_id`。这些形态都会被现有输入层拒绝
（`internal/service/session/profile.go`、`internal/service/adminuser/validate.go`），所以是纯存量
遗留，不是仍在产生的问题。该列把这个事实暴露给前端，用于引导用户补全。

**纯软提示**：没有任何认证或鉴权路径读取它，也没有任何端点因它为 `true` 而拒绝请求。

**为什么是生成列，而不是 `CHECK ... NOT VALID`**：`NOT VALID` 只跳过建约束时的全表校验，
之后**任何** UPDATE 都要整行过约束，包括不涉及问题列的更新。本服务写 `user` 行的路径包含
`token_version` 递增（改密码 / 降权 / 关号，即「cut access now」）与旧密码就地重哈希。
若用 `NOT VALID`，一个 `name` 为空的账号将无法改密码、无法封禁、无法撤销 token ——
数据质量问题升级为拒绝服务。生成列没有这种耦合：它是本行值的纯函数，用户补齐字段后自动
翻回 `false`，且 PostgreSQL 拒绝任何直接写入（应用侧对应 `gorm:"->"` 只读标签）。

**为什么包含 `qq_number`**：`name` / `phone_number` / `qq_number` / `major` 四个可自助补的
NOT NULL 资料字段一视同仁，为空即为待补全。旧库没有该字段，迁移账号此列全空，老用户首次登录被要求补全一次正是引导式补全的目的。

**为什么不含 `college`**：`'其他'` 是合法的 `college_enum` 成员，行内没有任何信息能区分
「迁移填了默认值」与「用户真的选了其他」，判脏会产生用户无法诚实消除的提示。这一排除是零代价的：
实测持有该默认值的行同时 `phone_number` 与 `major` 为空，已被覆盖。

**`sl_profile_is_blank` 为何要显式列出空白字符集**：PostgreSQL 单参数 `btrim(text)` 只裁 ASCII
空格，而 Go 的 `strings.TrimSpace` 裁剪整个 Unicode 空白集。若写成 `btrim(name) = ''`，一个
`name` 只含 NBSP 的账号会被判为「已完成」，而 `PUT /user/profile` 的 `TrimSpace` 认为它是空、
拒绝任何提交 —— 用户被告知一切正常却什么都改不了。该函数的字符集即 Go 的口径
（`unicode.IsSpace` 加 U+0085、U+00A0），与 `internal/validate.IsBlank` 成对，由
`TestProfileCompletenessMatchesSQL` 用同一组输入喂两侧来防漂移。零宽字符（U+200B..U+200D、
U+FEFF）两侧都不算空白，由 `validate.HasControlCharacter` 负责。

`name` 与 `student_id` 的比较忽略大小写：迁移数据中同时存在 `B24040525` 与 `b24040525` 两种形式。

配套 `idx_user_profile_needs_completion`（部分索引，`WHERE profile_needs_completion`）支撑管理台
按 `?needs_completion=true` 列出待补全账号。

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

刻意**无外键**：审计行需要比它命名的客户端注册存活得更久。`ON DELETE SET NULL` 会在注销客户端时把历史悄悄改写成「无凭证」，`RESTRICT` 则会让注销客户端卡在自己的审计尾巴上。同样**未加索引**：基数目前约为 1（仅一个委派客户端），既有 `action` 索引已把常用过滤切得足够小，且表有 90 天上限——等该过滤真有量再按 `EXPLAIN` 决定。

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

> **V009 起**：本表只承载「一次性授权码」。用户授权过的应用记录改存 [oauth_grants 授权记录](#oauth_grants-授权记录)，「已授权应用」列表不再以本表为数据源。

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

> 此表无 `updated_at`。生命周期为「创建 → 标记已用」。已使用 + 已过期的 code 由 API 内 retention worker 统一清理；V006 增设全量 `expires_at` 索引 `idx_oauth_authorizations_expires_at_all`，过期行按索引定位，无需 seq scan

## alumni_requests 校友建号申请

V011 新增。已毕业成员没有 `@sast.fun` 邮箱、学生邮箱也已停用，注册白名单（`login_email`
域名限制 + V001 触发器 `auto_set_email_type`）会阻止其自助注册；管理员建号能解决，但校友
侧没有入口去「请求建号」。此表就是那个入口：结构化工单，管理员在控制台审批，同一事务内
建号并写入审批结果。

**身份核验始终是人工的。** 工单化自动的是转录劳动，不是核验责任——学号加姓名在毕业生群体
里不是秘密，且 SMTP 发件人可伪造，任何「收到邮件即自动通过」的设计等于给任意人开号能力。
这也是邮件解析方案被否的原因（`internal/mailer` 只有出站 SMTP，无 IMAP/inbound）。

```sql
CREATE TYPE alumni_request_status_enum AS ENUM ('pending', 'approved', 'rejected');

CREATE TABLE alumni_requests (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    student_id      TEXT NOT NULL,
    login_email     TEXT NOT NULL,
    personal_email  TEXT NOT NULL,
    phone_number    TEXT NOT NULL,
    qq_number       TEXT NOT NULL,
    college         college_enum NOT NULL DEFAULT '其他',
    major           TEXT NOT NULL,
    join_year       TEXT NOT NULL,
    department_note TEXT NOT NULL DEFAULT '',
    note            TEXT NOT NULL DEFAULT '',
    status          alumni_request_status_enum NOT NULL DEFAULT 'pending',
    reject_reason   TEXT NOT NULL DEFAULT '',
    created_user_id BIGINT REFERENCES "user"(id) ON DELETE SET NULL,
    reviewed_by     BIGINT REFERENCES "user"(id) ON DELETE SET NULL,
    reviewed_at     TIMESTAMPTZ,
    notified_at     TIMESTAMPTZ,
    notify_attempts INT NOT NULL DEFAULT 0,
    client_ip       TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX uq_alumni_requests_pending_student
    ON alumni_requests (lower(btrim(student_id))) WHERE status = 'pending';
```

### intent 两种意图（V013）

V013 加列 `intent TEXT NOT NULL DEFAULT 'provision'`，不用 enum 类型：提交时写一次、从不修改、规则在
`internal/model` 的 `Valid()`。两种意图共用同一张表、同一个 partial unique index（一个学号不能同时挂一张
provision 单和一张 recover 单）和同一条投递链路：

| intent | 审批动作 | 提交端占用检查差异 |
|--------|----------|--------------------|
| `provision` | 开新号（含生成的密码哈希与 `retired_sast` 状态） | 学号**必须不存在**；两个地址都不能已被任何账号占用 |
| `recover` | 给该学号现有账号直绑 `personal_email` 恢复访问，不建号 | 学号**必须存在**且 `login_email` 与账号登记一致；仅检查个人邮箱占用 |

recover 是比开新号更敏感的动作：它把一个能收重置验证码的邮箱绑到现役账号上。技术护栏在审批事务内：先锁工单
行再锁 user 行（顺序与其它写入不构成环），锁定后重验登录邮箱一致性；已有第三方绑定一概不动（解绑永远需要密
码）；每账号 ≤2 的 V001 触发器是自然闸门。安全下限仍是审批纪律——控制台须以高危操作呈现。

```sql
CREATE INDEX idx_alumni_requests_status_created
    ON alumni_requests (status, created_at DESC);

CREATE INDEX idx_alumni_requests_pending_notification
    ON alumni_requests (id) WHERE status <> 'pending' AND notified_at IS NULL;

CREATE TRIGGER trg_alumni_requests_updated_at
    BEFORE UPDATE ON alumni_requests FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
```

### 两个邮箱

| 列 | 角色 |
|----|------|
| `login_email` | 原学号邮箱，审批后成为账号的登录身份。**仍限 `@njupt.edu.cn` / `@sast.fun`**——V001 触发器 `auto_set_email_type` 依赖该域名派生 `email_type`，放宽白名单会让写入在数据库层抛裸异常 |
| `personal_email` | 可正常收信的第三方邮箱，审批后在同一事务内直绑为 `other_mail` 身份。**结果通知与自助改密都发往这里**，不是 `login_email`——后者正是那个已停用的学生邮箱，发过去等于不发 |

两者不能相同：V005 的 `forbid_login_email_as_identity` / `forbid_identity_as_login_email`
禁止同一地址既是 `login_email` 又是 `other_mail` 身份。服务层在提交时就用
`ExistsAsEmailAnywhere` 预检两个地址，让申请人当场知道冲突，而不是等到审批时——那时人已经
走了，管理员拿着一张改不动的工单。

`personal_email` **不加唯一约束**：占位判定的权威在 `user` / `identities` 两表，工单表再存
一份判据只会漂移。

### 列宽与 V010

字段用 `TEXT` 而非 `VARCHAR(n)`：长度规则在 `internal/validate` 的常量里，两条建号路径共读
同一份，schema 再写一份就多一处 ALTER TABLE 必须找到的副本。但**服务层必须按 V001 列宽校验
那些将被拷进 `user` 表的字段**（`name` 255 / `phone_number` 20 / `qq_number` 20 /
`student_id` 50 / `major` 50 / `login_email` 255），否则工单会收下一个审批时必定失败的值。

服务层还有两条**比管理员建号更严**的规则，都来自 V010 的生成列
[`profile_needs_completion`](#user-用户表)：

- `major` 必填（管理员建号允许为空）
- `name` 不能等于 `student_id`（大小写与空白归一后比较，复用 `validate.IncompleteProfileFields`
  而非本地重写，以保证与 SQL 判据同源）

放宽任一条，审批建出的新号一登录就被前端赶去资料补全页——为了校友从未被要求填写的字段。
集成测试对这条判据做了正反两向断言：通过的工单建出的账号 `profile_needs_completion` 必须
为 false，而 `major` 为空的工单建出的必须为 true（否则第一条断言是空转）。

### 唯一索引为何是部分的

`uq_alumni_requests_pending_student` 只约束 `status = 'pending'`：同一学号同时只允许一条
待审申请（防重复刷屏），但**已驳回的不占名额**——修正信息后重新提交是这个流程的核心前提。

索引键是 `lower(btrim(student_id))`，因为上一代数据库的导入同时产出了 `B24040525` 与
`b24040525`，大小写敏感的索引会漏掉一半。

### 审批事务

审批是**一个事务**做三件事：锁工单行（`SELECT ... FOR UPDATE`）→ 建号 → 回写审批结果。
拆开会产生两种都很糟的中间态：

- 账号已建、工单仍 pending：邀请第二次审批，而重试会撞上第一次插入的学号唯一索引——管理员
  看到「学号已被占用」，占用者正是系统自己刚建的账号
- 工单已判、账号没建：校友拿着一封通过邮件，去登录一个不存在的账号

行锁是控制台按钮被双击时的保障：第二个事务阻塞到第一个提交，然后读到 `status = 'approved'`，
返回 42204 而不是再建一次。事务体在 repository 层（`createAdminUserInTransaction` 从
`CreateAdminUser` 抽出后复用），服务层传入映射回调——本仓库 `internal/service` 零 gorm
import，把事务交给服务层会破掉分层。

任一步失败整体回滚，工单留 `pending`，管理员可改字段重试。

### 通知投递状态

| 列 | 语义 |
|----|------|
| `notify_attempts` | 每次投递**之前**递增 |
| `notified_at` | 仅在 SMTP 接受后写入 |

顺序是刻意的：进程在发信中途被杀时，`notify_attempts` 已增而 `notified_at` 仍为 NULL，读作
「试过但未确认送达」——这正是真实状态。事后才递增会丢掉尝试痕迹，控制台会把这条工单显示成
从未处理过。

`idx_alumni_requests_pending_notification` 是部分索引，只收「已处理但未通知」的行：健康工单
的 `notified_at` 非空，永不进索引。控制台按 `notified=false` 查的就是这份积压。

通知状态之所以入库而不是只靠 channel 与日志：通过邮件是校友唯一的「去 `/reset` 设置密码」
指引，丢了等于建号白做，而队列长度与 slog 都不可查询。配套有手动重发端点。

### 其他约定

- `created_user_id` / `reviewed_by` 用 `ON DELETE SET NULL`：账号被注销后工单历史仍需保留
- `client_ip` **不出现在任何响应里**：留作滥用追溯与限流取证，审批工单用不到它，把一个可
  关联到具体个人的网络标识复制到读接口上只是扩大暴露面
- `updated_at` 复用 V001 的 `update_updated_at_column()`，不新建函数；`down` 迁移**不得**
  drop 它——那是 V001 的，还有四张表在用
- `college` 直接复用 `college_enum`，不新造枚举

## oauth_grants 授权记录

V009 新增。记录用户在同意页**授权过哪些应用**（consent history），是「已授权应用」列表
（`GET /oauth/grants`）的唯一数据源。**长效数据**：由 consent 时与授权码在同一个事务里
upsert，撤销时删除，retention worker 永不清理（见[清理策略](#清理策略说明)）。

```sql
CREATE TABLE oauth_grants (
    user_id    BIGINT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    client_id  BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes     TEXT[] NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, client_id)
);
CREATE INDEX idx_oauth_grants_client_id ON oauth_grants(client_id);
```

|字段名|说明|
|---|---|
|`user_id`||
|`client_id`||
|`scopes`|该用户**实际同意**的 scope（consent 时点），不是客户端注册的 scope|
|`granted_at`|最近一次同意时间（即列表的 `last_authorized_at`）|

> 每 user×client 一行：重复 consent 是 upsert，刷新 `scopes` / `granted_at`，不累积历史
> 行。历史审计在 `audit_logs`（`oauth_authorize` granted / `oauth_grant_revoke`，保留 90 天），
> 本表只承载当前态。列表 JOIN `oauth_clients` 实时取展示字段（`client_name` / `is_active`
> 等），不落地进 grant 行；disabled client 的 grant 照列。撤销（`DELETE /oauth/grants/:client_id`）
> 在删除本表行的同时删除 `oauth_authorizations` 行——后者杀掉在途未兑换授权码，否则撤销
> 前几分钟内签发的 code 仍可兑换出新 token。

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

> 此表无 `updated_at`。生命周期为「UPSERT → 认领 → 投递成功 DELETE / 过期清理」。`claim_token` + `claimed_until` 实现分布式 worker 的乐观锁认领，避免重复投递。

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
| `oauth_refresh_tokens` | 已撤销且 `sequence > 0`；或整个 family 已死（无任何未撤销且未过期的成员） | `expires_at` + 24h | 两个分支：轮换掉的行（`revoked_at` 已设）由 V001 的部分索引服务；死族分支还包括从未旋转的 sequence-0 行（`revoked_at IS NULL`），其外层 `expires_at` 谓词由 **V008** 的 `idx_oauth_refresh_tokens_expires_at_live` 服务，族内探测用 `family_id` 索引。**必须保留每个存活 family 的 sequence-0 行**：`FindFamilyOriginCreatedAt`（family 首授权时刻，`created_at`）是 capability 封顶（`JWT_REFRESH_CAPABILITY_MAX_LIFETIME`）与轮换一致性检查的基准，而该行从首次轮换起就带有 `revoked_at`。只要 family 还在轮换，它会活得比自己的 `expires_at` 更久；删掉会让刷新流程撤销整个 family 并返回 500——即用户被强制登出。每个 family 长期留一行，是换取 capability 封顶基准的代价 |
| `audit_logs` | 超过保留期 | `created_at` + 90d | 90 天（PRD §9）是**默认值**：审计日志在这里属运维用途而非合规强制，可调大以保留更多历史，也可收紧至 30 天下限；低于下限启动时拒绝，避免误配到「事故排查时相关记录已被删」的程度 |
| `alumni_requests` | 已审批（approved/rejected）且超过保留期 | `reviewed_at` + 180d | **pending 永不清理**，无论多久：三天处理时限只是前端文案，后端不做硬限制，删掉一条未审的申请是丢掉某人的请求而不是让它过期。窗口从 `reviewed_at` 起算而非 `created_at`——保留期的钟在「被决定」时才开始走，未审的没有起点。谓词显式带 `reviewed_at IS NOT NULL`：有状态但无时间戳的行否则会被拿去和一个它无值可比的 cutoff 比较。部分索引 `idx_alumni_requests_pending_notification` 服务的是通知积压视图，不是本清理 |

`oauth_grants` 不在此列，且**刻意永不清理**：授权记录是长效 consent history（当前态，历史
审计在 `audit_logs`），不是一次性凭据。把它加进这张表会重新制造 V009 之前「已授权应用列表
随授权码被清空」的旧 bug——后续编辑请勿添加。

`token_blacklist_outbox` 不在此列：`sessionworker.TokenBlacklist` 已负责清理它，再加一个
清理者只会让两者竞争同一张表。

单条语句删除的行数受 `RETENTION_BATCH_SIZE` 限制，扫到满批就继续下一批，直到某批不满为止；
单轮最多 20 批，剩余积压留给下一轮，避免长期未清理的表占用在线流量所需的连接池份额。

---

### 建表顺序

1. 枚举类型（8 个 CREATE TYPE，含 V011 的 alumni_request_status_enum）

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

12. `oauth_grants` 表（V009，FK → user, oauth_clients）

12.1 `sl_profile_is_blank()` 函数与 `"user".profile_needs_completion` 生成列（V010，生成列依赖该函数，顺序不可反；`down` 时先删列再删函数）

12.2 `alumni_requests` 表（V011，FK → user ×2，均 ON DELETE SET NULL；复用 V001 的 `update_updated_at_column()`，`down` 时不得 drop 该函数）

13. 所有索引

14. 所有触发器

15. 索引/触发器复核（清理由 API 内 retention worker 执行，不使用 pg_cron）
