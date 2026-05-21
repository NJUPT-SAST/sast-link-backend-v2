# SAST Link Backend V2 数据库设计文档

> 状态：已确认
> 日期：2026-05-19
> 版本：v1.0
> 数据库：PostgreSQL 15+

---

## 1. 概述

本文档定义 SAST Link Backend V2 的完整数据库 Schema、与老 Schema 的映射关系、数据迁移脚本以及 GORM 模型定义。

### 1.1 设计原则

1. **修复老 Schema 所有缺陷**：外键约束、类型统一、命名规范、索引齐全
2. **兼容老数据**：迁移脚本将老数据完整导入新 Schema
3. **保留核心字段名**：前端依赖的 JSON 字段名保持不变
4. **时间戳统一**：所有时间字段使用 `TIMESTAMPTZ`
5. **密码字段零改动**：`password_hash` 原样保留 SHA-512，与老后端完全一致

### 1.2 表清单

| 新表名 | 对应老表 | 说明 |
|--------|---------|------|
| `users` | `"user"` | 用户主表，避免 PostgreSQL 保留字 |
| `user_profiles` | `profile` | 用户资料表，移除 email 冗余 |
| `organizations` | `organize` | 组织架构表 |
| `career_records` | `carrer_records` | 生涯记录表，修复拼写 |
| `user_oauths` | `oauth2_info` + `user.qq_id/lark_id/github_id` | OAuth 绑定表，统一多 Provider |
| `admins` | `admin` | 管理员表，修复 user_id 类型 |
| `tickets` | — | 新增，Ticket 审计追踪 |
| `oauth2_clients` | `oauth2_clients` | OAuth2 客户端表，保留（有外部系统依赖） |
| `oauth2_tokens` | `oauth2_tokens` | OAuth2 Token 表，保留 |

---

## 2. 新 Schema 完整 DDL

### 2.1 枚举类型

```sql
-- 用户状态
CREATE TYPE user_status AS ENUM ('active', 'suspended', 'deleted');

-- OAuth 提供商
CREATE TYPE oauth_provider AS ENUM ('feishu', 'github', 'microsoft', 'qq');

-- Ticket 类型
CREATE TYPE ticket_type AS ENUM ('register', 'login', 'reset_password', 'oauth_bind');

-- Ticket 状态
CREATE TYPE ticket_status AS ENUM ('pending', 'verified', 'used', 'expired');

-- 管理员角色
CREATE TYPE admin_role AS ENUM ('admin', 'super_admin');
```

### 2.2 用户主表

```sql
CREATE TABLE users (
    id              BIGSERIAL PRIMARY KEY,
    uid             VARCHAR(255) UNIQUE NOT NULL,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255),                       -- SHA-512 hex (128位)，与老后端完全一致
    status          user_status NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE users IS '用户主表';
COMMENT ON COLUMN users.uid IS '学号，如 B21010101';
COMMENT ON COLUMN users.email IS '邮箱，如 B21010101@njupt.edu.cn';
COMMENT ON COLUMN users.password_hash IS '密码哈希 SHA-512 hex (128位)，与老后端完全一致，OAuth-only 用户可为 NULL';
COMMENT ON COLUMN users.status IS '用户状态：active-正常, suspended-冻结, deleted-已删除';

-- 索引
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_uid ON users(uid);
CREATE INDEX idx_users_status ON users(status);
```

### 2.3 用户资料表

```sql
CREATE TABLE user_profiles (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    nickname    VARCHAR(255) NOT NULL,
    org_id      SMALLINT NOT NULL DEFAULT -1,
    bio         TEXT,
    avatar      VARCHAR(255),
    link        JSONB DEFAULT '[]',
    badge       JSONB DEFAULT '[]',
    hide        JSONB DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE user_profiles IS '用户资料扩展表';
COMMENT ON COLUMN user_profiles.user_id IS '关联 users.id';
COMMENT ON COLUMN user_profiles.nickname IS '昵称';
COMMENT ON COLUMN user_profiles.org_id IS '当前所属组织 ID，-1 表示未分配';
COMMENT ON COLUMN user_profiles.bio IS '自我介绍';
COMMENT ON COLUMN user_profiles.avatar IS '头像 OSS URL';
COMMENT ON COLUMN user_profiles.link IS '社交链接数组，JSONB 格式';
COMMENT ON COLUMN user_profiles.badge IS '纪念卡数组，JSONB 格式，字段名 created_at（Go/GORM 标准命名）';
COMMENT ON COLUMN user_profiles.hide IS '隐藏字段数组，JSONB 格式';

-- 索引
CREATE INDEX idx_user_profiles_user_id ON user_profiles(user_id);
CREATE INDEX idx_user_profiles_org_id ON user_profiles(org_id);
```

### 2.4 组织架构表

```sql
CREATE TABLE organizations (
    id      SMALLSERIAL PRIMARY KEY,
    dep     VARCHAR(255) NOT NULL,
    org     VARCHAR(255)
);

COMMENT ON TABLE organizations IS '组织架构/部门表';
COMMENT ON COLUMN organizations.dep IS '部门名称';
COMMENT ON COLUMN organizations.org IS '组/组织名称';
```

### 2.5 生涯记录表

```sql
CREATE TABLE career_records (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      SMALLINT NOT NULL REFERENCES organizations(id),
    grade       SMALLINT NOT NULL,
    position    VARCHAR(20),
    is_deleted  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE career_records IS '用户生涯/任职记录表';
COMMENT ON COLUMN career_records.user_id IS '关联 users.id';
COMMENT ON COLUMN career_records.org_id IS '关联 organizations.id';
COMMENT ON COLUMN career_records.grade IS '届数，如 2023';
COMMENT ON COLUMN career_records.position IS '职位：部员/讲师/组长/部长/主席';
COMMENT ON COLUMN career_records.is_deleted IS '假删标记';

-- 索引
CREATE INDEX idx_career_records_user_id ON career_records(user_id);
CREATE INDEX idx_career_records_org_grade ON career_records(org_id, grade);
CREATE INDEX idx_career_records_user_grade ON career_records(user_id, grade);
```

### 2.6 OAuth 绑定表

```sql
CREATE TABLE user_oauths (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider            oauth_provider NOT NULL,
    provider_user_id    VARCHAR(255) NOT NULL,
    provider_email      VARCHAR(255),
    provider_name       VARCHAR(255),
    provider_avatar     VARCHAR(255),
    access_token        TEXT,
    refresh_token       TEXT,
    token_expires_at    TIMESTAMPTZ,
    raw_data            JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

COMMENT ON TABLE user_oauths IS 'OAuth 第三方登录绑定表';
COMMENT ON COLUMN user_oauths.user_id IS '关联 users.id';
COMMENT ON COLUMN user_oauths.provider IS 'OAuth 提供商';
COMMENT ON COLUMN user_oauths.provider_user_id IS '第三方系统用户唯一标识';
COMMENT ON COLUMN user_oauths.provider_email IS '第三方系统邮箱';
COMMENT ON COLUMN user_oauths.provider_name IS '第三方系统用户名';
COMMENT ON COLUMN user_oauths.provider_avatar IS '第三方系统头像 URL';
COMMENT ON COLUMN user_oauths.access_token IS '访问令牌（加密存储）';
COMMENT ON COLUMN user_oauths.refresh_token IS '刷新令牌（加密存储）';
COMMENT ON COLUMN user_oauths.raw_data IS '原始响应数据';

-- 索引
CREATE INDEX idx_user_oauths_user_id ON user_oauths(user_id);
CREATE INDEX idx_user_oauths_provider ON user_oauths(provider);
```

### 2.7 OAuth2 客户端表

```sql
CREATE TABLE oauth2_clients (
    id              BIGSERIAL PRIMARY KEY,
    client_id       VARCHAR(255) UNIQUE NOT NULL,
    client_secret   VARCHAR(255) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    redirect_uris   JSONB NOT NULL DEFAULT '[]',
    scopes          JSONB NOT NULL DEFAULT '[]',
    created_by      BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE oauth2_clients IS 'OAuth2 授权服务端客户端表';
COMMENT ON COLUMN oauth2_clients.client_id IS '客户端标识';
COMMENT ON COLUMN oauth2_clients.redirect_uris IS '允许的回调地址数组';
COMMENT ON COLUMN oauth2_clients.scopes IS '允许的 scope 数组';

CREATE INDEX idx_oauth2_clients_client_id ON oauth2_clients(client_id);
```

### 2.8 OAuth2 Token 表

```sql
CREATE TABLE oauth2_tokens (
    id              BIGSERIAL PRIMARY KEY,
    client_id       VARCHAR(255) NOT NULL,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_token    VARCHAR(255) UNIQUE NOT NULL,
    refresh_token   VARCHAR(255) UNIQUE NOT NULL,
    scope           VARCHAR(255),
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE oauth2_tokens IS 'OAuth2 授权服务端 Token 表';
COMMENT ON COLUMN oauth2_tokens.access_token IS 'Access Token（JWT）';
COMMENT ON COLUMN oauth2_tokens.refresh_token IS 'Refresh Token（随机串）';

CREATE INDEX idx_oauth2_tokens_access ON oauth2_tokens(access_token);
CREATE INDEX idx_oauth2_tokens_refresh ON oauth2_tokens(refresh_token);
CREATE INDEX idx_oauth2_tokens_user ON oauth2_tokens(user_id);
```

### 2.9 管理员表

```sql
CREATE TABLE admins (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    role        admin_role NOT NULL DEFAULT 'admin',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE admins IS '管理员表';
COMMENT ON COLUMN admins.user_id IS '关联 users.id';
COMMENT ON COLUMN admins.role IS '管理员角色：admin-普通管理员, super_admin-超级管理员';

-- 索引
CREATE INDEX idx_admins_user_id ON admins(user_id);
CREATE INDEX idx_admins_role ON admins(role);
```

### 2.8 Ticket 审计表

```sql
CREATE TABLE tickets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket      VARCHAR(255) UNIQUE NOT NULL,
    type        ticket_type NOT NULL,
    user_id     BIGINT REFERENCES users(id) ON DELETE SET NULL,
    email       VARCHAR(255) NOT NULL,
    status      ticket_status NOT NULL DEFAULT 'pending',
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE tickets IS 'Ticket 审计追踪表（实际状态仍存 Redis，此表用于持久化审计）';
COMMENT ON COLUMN tickets.ticket IS 'Ticket 字符串';
COMMENT ON COLUMN tickets.type IS 'Ticket 类型';
COMMENT ON COLUMN tickets.status IS 'Ticket 状态';
COMMENT ON COLUMN tickets.expires_at IS '过期时间';
COMMENT ON COLUMN tickets.used_at IS '使用时间';

-- 索引
CREATE INDEX idx_tickets_ticket ON tickets(ticket);
CREATE INDEX idx_tickets_email ON tickets(email);
CREATE INDEX idx_tickets_user_id ON tickets(user_id);
CREATE INDEX idx_tickets_status ON tickets(status);
CREATE INDEX idx_tickets_expires_at ON tickets(expires_at);
```

### 2.9 完整 Schema 关系图

```
+----------------+       +------------------+       +------------------+
|     users      |<----->|  user_profiles   |       |  career_records  |
+----------------+       +------------------+       +------------------+
   |      ^                   |    |                      |      |
   |      |                   |    |                      |      |
   |      +-------------------+    +----------------------+      |
   |         (ON DELETE CASCADE)   (ON DELETE CASCADE)           |
   |                                                             |
   |         +------------------+                                |
   |         |      admins      |                                |
   |         +------------------+                                |
   |              |                                              |
   |              | (ON DELETE CASCADE)                          |
   |              v                                              |
   |         +------------------+                                |
   +-------->|   user_oauths    |                                |
   |         +------------------+                                |
   |              |                                              |
   |              | (ON DELETE CASCADE)                          |
   |              v                                              |
   |         +------------------+                                |
   +-------->|     tickets      |                                |
   |         +------------------+                                |
   |                                                             |
   |         +------------------+                                |
   +-------->|  organizations   |<-------------------------------+
             +------------------+         (ON DELETE RESTRICT)
```

---

## 3. 老 Schema → 新 Schema 映射表

### 3.1 `"user"` → `users`

| 老字段 | 老类型 | 新字段 | 新类型 | 变更说明 |
|--------|--------|--------|--------|---------|
| `id` | `SERIAL` (int4) | `id` | `BIGSERIAL` (int8) | 类型扩大，数据直接导入 |
| `created_at` | `timestamp` | `created_at` | `TIMESTAMPTZ` | 类型统一为带时区 |
| `email` | `varchar(255)` | `email` | `VARCHAR(255)` | 不变，新增 `UNIQUE` 约束 |
| `uid` | `varchar(255)` | `uid` | `VARCHAR(255)` | 不变，改为独立 `UNIQUE` |
| `qq_id` | `varchar(255)` | — | — | **移除**，数据迁移到 `user_oauths` |
| `lark_id` | `varchar(255)` | — | — | **移除**，数据迁移到 `user_oauths` |
| `github_id` | `varchar(255)` | — | — | **移除**，数据迁移到 `user_oauths` |
| `wechat_id` | `varchar(255)` | — | — | **移除**，数据不迁移（微信登录不在支持范围内） |
| `is_deleted` | `bool` | `status` | `user_status` | **变更**：`is_deleted=true` → `'deleted'`，否则 `'active'` |
| `password` | `varchar(255)` | `password_hash` | `VARCHAR(255)` | **重命名**，数据原样复制 |
| — | — | `updated_at` | `TIMESTAMPTZ` | **新增**，老数据设为 `created_at` 值 |

**数据清洗规则**：
- `status` 推导：`CASE WHEN is_deleted THEN 'deleted'::user_status ELSE 'active'::user_status END`
- `updated_at` 初始值：`created_at`

### 3.2 `profile` → `user_profiles`

| 老字段 | 老类型 | 新字段 | 新类型 | 变更说明 |
|--------|--------|--------|--------|---------|
| `id` | `SERIAL` (int4) | `id` | `BIGSERIAL` (int8) | 类型扩大 |
| `user_id` | `int4` | `user_id` | `BIGINT` | 类型扩大，新增 `FOREIGN KEY` |
| `nickname` | `varchar(255)` | `nickname` | `VARCHAR(255)` | 不变 |
| `org_id` | `int2` | `org_id` | `SMALLINT` | 不变，默认值 `-1` |
| `bio` | `varchar(255)` | `bio` | `TEXT` | 类型扩大为 `TEXT` |
| `email` | `varchar(255)` | — | — | **移除**，从 `users.email` JOIN 获取 |
| `badge` | `json` | `badge` | `JSONB` | 类型优化为 `JSONB` |
| `link` | `varchar[]` | `link` | `JSONB` | **类型变更**：数组 → JSONB 数组 |
| `avatar` | `varchar(255)` | `avatar` | `VARCHAR(255)` | 不变 |
| `is_deleted` | `bool` | — | — | **移除**，假删由 `users.status` 统一管理 |
| `hide` | `varchar[]` | `hide` | `JSONB` | **类型变更**：数组 → JSONB 数组 |
| — | — | `created_at` | `TIMESTAMPTZ` | **新增**，设为 `NOW()` |
| — | — | `updated_at` | `TIMESTAMPTZ` | **新增**，设为 `NOW()` |

**数据清洗规则**：
- `link` 转换：`to_jsonb(link)` 或 `COALESCE(to_jsonb(link), '[]'::jsonb)`
- `hide` 转换：`to_jsonb(hide)` 或 `COALESCE(to_jsonb(hide), '[]'::jsonb)`
- `badge` 转换：`COALESCE(badge::jsonb, '[]'::jsonb)`（老数据可能为 NULL）

### 3.3 `organize` → `organizations`

| 老字段 | 老类型 | 新字段 | 新类型 | 变更说明 |
|--------|--------|--------|--------|---------|
| `id` | `SERIAL` (int4) | `id` | `SMALLSERIAL` (int2) | 类型缩小（数据量极小，安全） |
| `dep` | `varchar(255)` | `dep` | `VARCHAR(255)` | 不变 |
| `org` | `varchar(255)` | `org` | `VARCHAR(255)` | 不变 |

### 3.4 `carrer_records` → `career_records`

| 老字段 | 老类型 | 新字段 | 新类型 | 变更说明 |
|--------|--------|--------|--------|---------|
| `id` | `SERIAL` (int4) | `id` | `BIGSERIAL` (int8) | 类型扩大 |
| `user_id` | `int4` | `user_id` | `BIGINT` | 类型扩大，新增 `FOREIGN KEY` |
| `org_id` | `int2` | `org_id` | `SMALLINT` | 不变，新增 `FOREIGN KEY` |
| `grade` | `int2` | `grade` | `SMALLINT` | 不变 |
| `is_delete` | `bool` | `is_deleted` | `BOOLEAN` | **重命名** |
| `position` | `varchar(2)` | `position` | `VARCHAR(20)` | 长度扩大 |
| — | — | `created_at` | `TIMESTAMPTZ` | **新增**，设为 `NOW()` |

### 3.5 `oauth2_info` → `user_oauths`

| 老字段 | 老类型 | 新字段 | 新类型 | 变更说明 |
|--------|--------|--------|--------|---------|
| `id` | `SERIAL` (int4) | `id` | `BIGSERIAL` (int8) | 类型扩大 |
| `client` | `varchar` | `provider` | `oauth_provider` | **重命名+类型变更**，需大小写映射 |
| `info` | `jsonb` | `raw_data` | `JSONB` | **重命名** |
| `oauth_user_id` | `varchar` | `provider_user_id` | `VARCHAR(255)` | **重命名** |
| `user_id` | `varchar` | `user_id` | `BIGINT` | **类型变更**：通过 `users.uid` JOIN 匹配 |
| — | — | `provider_email` | `VARCHAR(255)` | **新增**，从 `info` JSONB 提取 |
| — | — | `provider_name` | `VARCHAR(255)` | **新增**，从 `info` JSONB 提取 |
| — | — | `provider_avatar` | `VARCHAR(255)` | **新增**，从 `info` JSONB 提取 |
| — | — | `access_token` | `TEXT` | **新增** |
| — | — | `refresh_token` | `TEXT` | **新增** |
| — | — | `token_expires_at` | `TIMESTAMPTZ` | **新增** |
| — | — | `created_at` | `TIMESTAMPTZ` | **新增** |
| — | — | `updated_at` | `TIMESTAMPTZ` | **新增** |

**Provider 名称映射**：
| 老 `client` 值 | 新 `provider` 值 |
|---------------|-----------------|
| `Feishu` / `feishu` / `Lark` / `lark` | `'feishu'` |
| `GitHub` / `github` | `'github'` |
| `Microsoft` / `microsoft` | `'microsoft'` |
| `QQ` / `qq` | `'qq'` |

**数据清洗规则**：
- `user_id` 转换：通过 `JOIN users ON oauth2_info.user_id = users.uid` 获取 `users.id`
- 无法匹配的 `oauth2_info` 记录需记录到迁移日志，人工处理

### 3.6 `admin` → `admins`

| 老字段 | 老类型 | 新字段 | 新类型 | 变更说明 |
|--------|--------|--------|--------|---------|
| `id` | `SERIAL` (int4) | `id` | `BIGSERIAL` (int8) | 类型扩大 |
| `created_at` | `timestamp` | `created_at` | `TIMESTAMPTZ` | 类型统一 |
| `user_id` | `varchar(255)` | `user_id` | `BIGINT` | **类型变更**：通过 `users.uid` JOIN 匹配 |
| — | — | `role` | `admin_role` | **新增**，默认 `'admin'` |

**数据清洗规则**：
- `user_id` 转换：通过 `JOIN users ON admin.user_id = users.uid` 获取 `users.id`
- 无法匹配的 `admin` 记录需记录到迁移日志，人工处理

### 3.7 老 `user` 表 OAuth ID 字段 → `user_oauths`

老 `user` 表中的 `qq_id`、`lark_id`、`github_id` 字段数据需迁移到 `user_oauths` 表（`wechat_id` 不迁移，微信登录不在 V1 支持范围内）：

| 老字段 | Provider | 新表记录 |
|--------|----------|---------|
| `qq_id` | `'qq'` | `provider='qq', provider_user_id=qq_id` |
| `lark_id` | `'feishu'` | `provider='feishu', provider_user_id=lark_id` |
| `github_id` | `'github'` | `provider='github', provider_user_id=github_id` |

**注意**：仅当字段值非 NULL 且非空字符串时插入记录。

---

## 4. 数据迁移脚本设计

### 4.1 迁移工具

使用 **golang-migrate** 管理迁移，文件命名规范：

```
migrations/
├── 000001_create_enums.up.sql
├── 000001_create_enums.down.sql
├── 000002_create_tables.up.sql
├── 000002_create_tables.down.sql
├── 000003_migrate_data.up.sql          -- 数据迁移（一次性）
├── 000003_migrate_data.down.sql        -- 数据回滚
└── 000004_drop_old_tables.up.sql       -- 确认无误后删除旧表
```

### 4.2 迁移步骤 1：创建枚举和表（000001 + 000002）

**Up**（`000001_create_enums.up.sql`）：

```sql
CREATE TYPE user_status AS ENUM ('active', 'suspended', 'deleted');
CREATE TYPE oauth_provider AS ENUM ('feishu', 'github', 'microsoft', 'qq');
CREATE TYPE ticket_type AS ENUM ('register', 'login', 'reset_password', 'oauth_bind');
CREATE TYPE ticket_status AS ENUM ('pending', 'verified', 'used', 'expired');
CREATE TYPE admin_role AS ENUM ('admin', 'super_admin');
```

**Down**（`000001_create_enums.down.sql`）：

```sql
DROP TYPE IF EXISTS admin_role CASCADE;
DROP TYPE IF EXISTS ticket_status CASCADE;
DROP TYPE IF EXISTS ticket_type CASCADE;
DROP TYPE IF EXISTS oauth_provider CASCADE;
DROP TYPE IF EXISTS user_status CASCADE;
```

**Up**（`000002_create_tables.up.sql`）：

```sql
-- users
CREATE TABLE users (
    id              BIGSERIAL PRIMARY KEY,
    uid             VARCHAR(255) UNIQUE NOT NULL,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255),
    status          user_status NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_uid ON users(uid);
CREATE INDEX idx_users_status ON users(status);

-- user_profiles
CREATE TABLE user_profiles (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    nickname    VARCHAR(255) NOT NULL,
    org_id      SMALLINT NOT NULL DEFAULT -1,
    bio         TEXT,
    avatar      VARCHAR(255),
    link        JSONB DEFAULT '[]',
    badge       JSONB DEFAULT '[]',
    hide        JSONB DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_profiles_user_id ON user_profiles(user_id);
CREATE INDEX idx_user_profiles_org_id ON user_profiles(org_id);

-- organizations
CREATE TABLE organizations (
    id      SMALLSERIAL PRIMARY KEY,
    dep     VARCHAR(255) NOT NULL,
    org     VARCHAR(255)
);

-- career_records
CREATE TABLE career_records (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      SMALLINT NOT NULL REFERENCES organizations(id),
    grade       SMALLINT NOT NULL,
    position    VARCHAR(20),
    is_deleted  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_career_records_user_id ON career_records(user_id);
CREATE INDEX idx_career_records_org_grade ON career_records(org_id, grade);
CREATE INDEX idx_career_records_user_grade ON career_records(user_id, grade);

-- user_oauths
CREATE TABLE user_oauths (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider            oauth_provider NOT NULL,
    provider_user_id    VARCHAR(255) NOT NULL,
    provider_email      VARCHAR(255),
    provider_name       VARCHAR(255),
    provider_avatar     VARCHAR(255),
    access_token        TEXT,
    refresh_token       TEXT,
    token_expires_at    TIMESTAMPTZ,
    raw_data            JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX idx_user_oauths_user_id ON user_oauths(user_id);
CREATE INDEX idx_user_oauths_provider ON user_oauths(provider);

-- admins
CREATE TABLE admins (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    role        admin_role NOT NULL DEFAULT 'admin',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_admins_user_id ON admins(user_id);
CREATE INDEX idx_admins_role ON admins(role);

-- tickets
CREATE TABLE tickets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket      VARCHAR(255) UNIQUE NOT NULL,
    type        ticket_type NOT NULL,
    user_id     BIGINT REFERENCES users(id) ON DELETE SET NULL,
    email       VARCHAR(255) NOT NULL,
    status      ticket_status NOT NULL DEFAULT 'pending',
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tickets_ticket ON tickets(ticket);
CREATE INDEX idx_tickets_email ON tickets(email);
CREATE INDEX idx_tickets_user_id ON tickets(user_id);
CREATE INDEX idx_tickets_status ON tickets(status);
CREATE INDEX idx_tickets_expires_at ON tickets(expires_at);
```

**Down**（`000002_create_tables.down.sql`）：

```sql
DROP TABLE IF EXISTS tickets CASCADE;
DROP TABLE IF EXISTS admins CASCADE;
DROP TABLE IF EXISTS user_oauths CASCADE;
DROP TABLE IF EXISTS career_records CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;
DROP TABLE IF EXISTS user_profiles CASCADE;
DROP TABLE IF EXISTS users CASCADE;
```

### 4.3 迁移步骤 2：数据迁移（000003）

**Up**（`000003_migrate_data.up.sql`）：

```sql
-- ============================================================
-- 数据迁移脚本：老 Schema → 新 Schema
-- 执行前请确保已完整备份数据库
-- ============================================================

-- 1. 迁移 organizations（无依赖，最先执行）
INSERT INTO organizations (id, dep, org)
SELECT id, dep, org
FROM organize;

-- 2. 迁移 users（核心表，其他表依赖它）
INSERT INTO users (id, uid, email, password_hash, status, created_at, updated_at)
SELECT
    id,
    uid,
    email,
    "password" AS password_hash,  -- 原样复制，零改动
    CASE WHEN is_deleted THEN 'deleted'::user_status ELSE 'active'::user_status END,
    created_at AT TIME ZONE 'UTC',
    created_at AT TIME ZONE 'UTC'
FROM "user";

-- 重置序列，确保后续插入 ID 正确
SELECT setval('users_id_seq', COALESCE((SELECT MAX(id) FROM users), 1), true);

-- 3. 迁移 user_profiles
INSERT INTO user_profiles (id, user_id, nickname, org_id, bio, avatar, link, badge, hide, created_at, updated_at)
SELECT
    id,
    user_id,
    nickname,
    org_id,
    bio,
    avatar,
    COALESCE(to_jsonb(link), '[]'::jsonb),
    COALESCE(badge::jsonb, '[]'::jsonb),
    COALESCE(to_jsonb(hide), '[]'::jsonb),
    NOW(),
    NOW()
FROM profile;

SELECT setval('user_profiles_id_seq', COALESCE((SELECT MAX(id) FROM user_profiles), 1), true);

-- 4. 迁移 career_records
INSERT INTO career_records (id, user_id, org_id, grade, position, is_deleted, created_at)
SELECT
    id,
    user_id,
    org_id,
    grade,
    "position",
    is_delete,
    NOW()
FROM carrer_records;

SELECT setval('career_records_id_seq', COALESCE((SELECT MAX(id) FROM career_records), 1), true);

-- 5. 迁移 user_oauths（来源1：oauth2_info 表）
INSERT INTO user_oauths (user_id, provider, provider_user_id, raw_data, created_at, updated_at)
SELECT
    u.id,
    CASE
        WHEN LOWER(o.client) IN ('feishu', 'lark') THEN 'feishu'::oauth_provider
        WHEN LOWER(o.client) = 'github' THEN 'github'::oauth_provider
        WHEN LOWER(o.client) = 'microsoft' THEN 'microsoft'::oauth_provider
        WHEN LOWER(o.client) = 'qq' THEN 'qq'::oauth_provider
        ELSE 'feishu'::oauth_provider  -- 默认值，需人工复核
    END,
    o.oauth_user_id,
    COALESCE(o.info, '{}'),
    NOW(),
    NOW()
FROM oauth2_info o
JOIN users u ON o.user_id = u.uid;  -- 通过 uid 匹配

-- 记录无法匹配的 oauth2_info 记录
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM oauth2_info o WHERE NOT EXISTS (SELECT 1 FROM users u WHERE o.user_id = u.uid)) THEN
        RAISE NOTICE '警告：存在无法匹配的 oauth2_info 记录，请检查迁移日志';
    END IF;
END $$;

-- 6. 迁移 user_oauths（来源2：user 表的 qq_id/lark_id/github_id）
-- qq_id
INSERT INTO user_oauths (user_id, provider, provider_user_id, created_at, updated_at)
SELECT id, 'qq'::oauth_provider, qq_id, NOW(), NOW()
FROM "user"
WHERE qq_id IS NOT NULL AND qq_id != '';

-- lark_id → feishu
INSERT INTO user_oauths (user_id, provider, provider_user_id, created_at, updated_at)
SELECT id, 'feishu'::oauth_provider, lark_id, NOW(), NOW()
FROM "user"
WHERE lark_id IS NOT NULL AND lark_id != '';

-- github_id
INSERT INTO user_oauths (user_id, provider, provider_user_id, created_at, updated_at)
SELECT id, 'github'::oauth_provider, github_id, NOW(), NOW()
FROM "user"
WHERE github_id IS NOT NULL AND github_id != '';

-- 注意：wechat_id 不迁移（微信登录不在 V1 支持范围内）

SELECT setval('user_oauths_id_seq', COALESCE((SELECT MAX(id) FROM user_oauths), 1), true);

-- 7. 迁移 admins
INSERT INTO admins (id, user_id, role, created_at)
SELECT
    a.id,
    u.id,
    'admin'::admin_role,
    a.created_at AT TIME ZONE 'UTC'
FROM admin a
JOIN users u ON a.user_id = u.uid;  -- 通过 uid 匹配

-- 记录无法匹配的 admin 记录
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM admin a WHERE NOT EXISTS (SELECT 1 FROM users u WHERE a.user_id = u.uid)) THEN
        RAISE NOTICE '警告：存在无法匹配的 admin 记录，请检查迁移日志';
    END IF;
END $$;

SELECT setval('admins_id_seq', COALESCE((SELECT MAX(id) FROM admins), 1), true);

-- 8. 验证数据完整性
DO $$
DECLARE
    user_count INT;
    profile_count INT;
    career_count INT;
    oauth_count INT;
    admin_count INT;
    org_count INT;
BEGIN
    SELECT COUNT(*) INTO user_count FROM users;
    SELECT COUNT(*) INTO profile_count FROM user_profiles;
    SELECT COUNT(*) INTO career_count FROM career_records;
    SELECT COUNT(*) INTO oauth_count FROM user_oauths;
    SELECT COUNT(*) INTO admin_count FROM admins;
    SELECT COUNT(*) INTO org_count FROM organizations;

    RAISE NOTICE '迁移完成统计：';
    RAISE NOTICE '  users: %', user_count;
    RAISE NOTICE '  user_profiles: %', profile_count;
    RAISE NOTICE '  career_records: %', career_count;
    RAISE NOTICE '  user_oauths: %', oauth_count;
    RAISE NOTICE '  admins: %', admin_count;
    RAISE NOTICE '  organizations: %', org_count;
END $$;
```

**Down**（`000003_migrate_data.down.sql`）—— 清空新表数据（保留表结构）：

```sql
-- 按依赖顺序清空数据
DELETE FROM tickets;
DELETE FROM admins;
DELETE FROM user_oauths;
DELETE FROM career_records;
DELETE FROM user_profiles;
DELETE FROM users;
DELETE FROM organizations;
```

### 4.4 迁移步骤 3：删除旧表（000004，可选，确认无误后执行）

**Up**（`000004_drop_old_tables.up.sql`）：

```sql
-- 仅在确认新系统运行稳定后执行
-- 执行前请再次确认备份可用

DROP TABLE IF EXISTS oauth2_tokens CASCADE;
DROP TABLE IF EXISTS oauth2_clients CASCADE;
DROP TABLE IF EXISTS oauth2_info CASCADE;
DROP TABLE IF EXISTS admin CASCADE;
DROP TABLE IF EXISTS carrer_records CASCADE;
DROP TABLE IF EXISTS profile CASCADE;
DROP TABLE IF EXISTS organize CASCADE;
DROP TABLE IF EXISTS "user" CASCADE;
```

**Down**：无（删除操作不可逆，回滚需从备份恢复）

---

## 5. 零风险迁移方案

### 5.1 停机迁移 vs 在线迁移评估

| 维度 | 停机迁移 | 在线迁移 |
|------|---------|---------|
| **复杂度** | 低 | 高（需双写、数据同步、冲突处理） |
| **风险** | 低 | 高 |
| **回滚难度** | 低（直接切回老系统） | 高（需处理数据不一致） |
| **对业务影响** | 有停机窗口 | 无停机 |
| **适用场景** | 数据量小、可接受短暂停机 | 数据量大、7x24 服务 |

**决策：采用停机迁移**

理由：
1. SAST Link 用户量小（校内系统），可接受分钟级停机
2. 老 Schema 到新 Schema 变更剧烈（表结构重命名、字段类型变更、外键新增），在线迁移复杂度极高
3. 停机迁移回滚简单，风险可控
4. 无实时交易类业务，无数据一致性强要求

### 5.2 迁移前准备

#### 5.2.1 环境准备

```bash
# 1. 确认 golang-migrate 已安装
migrate -version

# 2. 创建新数据库（建议与老库分离，便于回滚）
createdb -U sastlink sastlink_v2

# 3. 配置环境变量
export DATABASE_URL="postgres://sastlink:password@localhost:5432/sastlink_v2?sslmode=disable"
```

#### 5.2.2 备份策略

```bash
# 1. 完整逻辑备份（pg_dump）
pg_dump -U sastlink -h localhost -Fc sastlink > sastlink_backup_$(date +%Y%m%d_%H%M%S).dump

# 2. 物理备份（如使用 WAL 归档）
# 确认 pg_basebackup 或云厂商快照已启用

# 3. 备份验证（在隔离环境恢复测试）
pg_restore --clean --if-exists -d sastlink_test sastlink_backup_*.dump
```

**备份检查清单**：
- [ ] pg_dump 文件大小合理（与数据库大小匹配）
- [ ] pg_dump 文件能在测试环境成功恢复
- [ ] 云厂商快照已创建（如使用 RDS）
- [ ] 备份文件存储到异地（S3/对象存储）

### 5.3 迁移执行流程

```
T-30min   通知用户维护窗口
T-10min   停止应用写入（切维护页）
T-5min    执行最终备份
T-0min    开始迁移
  ├─ Step 1: 创建新数据库
  ├─ Step 2: 执行 000001_create_enums.up.sql
  ├─ Step 3: 执行 000002_create_tables.up.sql
  ├─ Step 4: 执行 000003_migrate_data.up.sql
  ├─ Step 5: 数据验证
  ├─ Step 6: 应用配置指向新数据库
  └─ Step 7: 启动应用， smoke test
T+Nmin    确认无误，开放服务
```

**详细命令**：

```bash
#!/bin/bash
set -euo pipefail

DB_URL="postgres://sastlink:password@localhost:5432/sastlink_v2?sslmode=disable"
MIGRATIONS_DIR="./migrations"
BACKUP_FILE="sastlink_backup_$(date +%Y%m%d_%H%M%S).dump"

echo "[1/7] 执行备份..."
pg_dump -U sastlink -h localhost -Fc sastlink > "$BACKUP_FILE"
echo "备份完成: $BACKUP_FILE"

echo "[2/7] 创建新数据库..."
dropdb --if-exists sastlink_v2
createdb -U sastlink sastlink_v2

echo "[3/7] 执行 Schema 迁移..."
migrate -database "$DB_URL" -path "$MIGRATIONS_DIR" up 2

echo "[4/7] 执行数据迁移..."
migrate -database "$DB_URL" -path "$MIGRATIONS_DIR" up 1

echo "[5/7] 数据验证..."
psql "$DB_URL" -c "SELECT 'users' as table, COUNT(*) as count FROM users
                   UNION ALL
                   SELECT 'user_profiles', COUNT(*) FROM user_profiles
                   UNION ALL
                   SELECT 'career_records', COUNT(*) FROM career_records
                   UNION ALL
                   SELECT 'user_oauths', COUNT(*) FROM user_oauths
                   UNION ALL
                   SELECT 'admins', COUNT(*) FROM admins
                   UNION ALL
                   SELECT 'organizations', COUNT(*) FROM organizations;"

echo "[6/7] 验证外键完整性..."
psql "$DB_URL" -c "SELECT
    tc.table_name,
    kcu.column_name,
    ccu.table_name AS foreign_table,
    ccu.column_name AS foreign_column
FROM information_schema.table_constraints tc
JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
JOIN information_schema.constraint_column_usage ccu ON ccu.constraint_name = tc.constraint_name
WHERE tc.constraint_type = 'FOREIGN KEY';"

echo "[7/7] 迁移完成！"
```

### 5.4 验证步骤

#### 5.4.1 数据量验证

```sql
-- 各表数据量应与老表一致
SELECT 'users' as tbl, COUNT(*) as cnt FROM users
UNION ALL SELECT 'user_profiles', COUNT(*) FROM user_profiles
UNION ALL SELECT 'career_records', COUNT(*) FROM career_records
UNION ALL SELECT 'organizations', COUNT(*) FROM organizations
UNION ALL SELECT 'admins', COUNT(*) FROM admins
UNION ALL SELECT 'user_oauths', COUNT(*) FROM user_oauths;
```

#### 5.4.2 关键字段验证

```sql
-- 1. 密码字段原样迁移验证（抽样检查）
SELECT u.id, u.uid, u.password_hash,
       CASE
           WHEN LENGTH(u.password_hash) = 128 THEN 'SHA-512'
           ELSE 'unknown'
       END as hash_type
FROM users u
LIMIT 5;

-- 2. admin.user_id 正确关联验证
SELECT a.id, a.user_id, u.uid, u.email
FROM admins a
JOIN users u ON a.user_id = u.id
LIMIT 5;

-- 3. user_oauths 关联验证
SELECT o.id, o.user_id, u.uid, o.provider, o.provider_user_id
FROM user_oauths o
JOIN users u ON o.user_id = u.id
LIMIT 10;

-- 4. 外键约束验证（应无孤儿记录）
SELECT 'orphan profiles' as check_item, COUNT(*)
FROM user_profiles p WHERE NOT EXISTS (SELECT 1 FROM users u WHERE p.user_id = u.id)
UNION ALL
SELECT 'orphan careers', COUNT(*)
FROM career_records c WHERE NOT EXISTS (SELECT 1 FROM users u WHERE c.user_id = u.id)
UNION ALL
SELECT 'orphan oauths', COUNT(*)
FROM user_oauths o WHERE NOT EXISTS (SELECT 1 FROM users u WHERE o.user_id = u.id)
UNION ALL
SELECT 'orphan admins', COUNT(*)
FROM admins a WHERE NOT EXISTS (SELECT 1 FROM users u WHERE a.user_id = u.id);

-- 5. 唯一约束验证
SELECT uid, COUNT(*) FROM users GROUP BY uid HAVING COUNT(*) > 1;
SELECT email, COUNT(*) FROM users GROUP BY email HAVING COUNT(*) > 1;
```

#### 5.4.3 应用层验证

- [ ] 用户登录（SHA-512 密码）
- [ ] OAuth 登录（飞书）
- [ ] OAuth 登录（GitHub）
- [ ] 获取用户资料
- [ ] 修改用户资料
- [ ] 管理员接口访问

### 5.5 回滚方案

#### 5.5.1 场景 A：迁移过程中失败（新库未启用）

```bash
# 直接删除新库，老库 untouched
dropdb sastlink_v2

# 恢复应用配置指向老库
# 启动应用
```

**恢复时间**：< 5 分钟

#### 5.5.2 场景 B：迁移完成但验证发现问题（新库已启用）

```bash
# 1. 立即停止新应用
# 2. 恢复应用配置指向老库
# 3. 启动老应用（老库数据未变动）

# 如需保留新库用于排查问题，可保留但不接入流量
```

**恢复时间**：< 5 分钟

#### 5.5.3 场景 C：运行一段时间后发现问题（新库已有新数据）

这是最复杂的场景，需要数据合并。

```bash
# 1. 立即停止新应用，防止进一步写入
# 2. 导出新库新增数据
pg_dump -U sastlink -h localhost --data-only \
  --table=users --table=user_profiles --table=career_records \
  --table=user_oauths --table=admins --table=tickets \
  sastlink_v2 > new_data.sql

# 3. 分析新增数据，制定合并策略（可能需要人工介入）
# 4. 从备份恢复老库
pg_restore -U sastlink -d sastlink --clean sastlink_backup_*.dump

# 5. 手动合并新增数据（或丢弃，视业务影响决定）
# 6. 恢复老应用
```

**预防措施**：
- 迁移后观察期设置为 24-48 小时
- 观察期内禁止大规模推广
- 关键操作（注册、修改密码）增加日志审计

#### 5.5.4 回滚决策矩阵

| 发现问题时间 | 影响范围 | 回滚动作 |
|-------------|---------|---------|
| 迁移执行中 | 无 | 删除新库，重试或修复脚本 |
| 验证阶段 | 无 | 切回老库，排查问题 |
| 上线后 < 1h | 极少新数据 | 切回老库，丢弃新数据 |
| 上线后 < 24h | 少量新数据 | 切回老库，人工合并新数据 |
| 上线后 > 24h | 大量新数据 | 不rollback，在新库修复问题 |

---

## 6. GORM 模型定义

```go
package domain

import (
    "time"

    "github.com/google/uuid"
    "gorm.io/gorm"
)

// ==================== 枚举类型 ====================

type UserStatus string

const (
    UserStatusActive    UserStatus = "active"
    UserStatusSuspended UserStatus = "suspended"
    UserStatusDeleted   UserStatus = "deleted"
)

type OAuthProvider string

const (
    OAuthProviderFeishu   OAuthProvider = "feishu"
    OAuthProviderGitHub   OAuthProvider = "github"
    OAuthProviderMicrosoft OAuthProvider = "microsoft"
    OAuthProviderQQ       OAuthProvider = "qq"
)

type TicketType string

const (
    TicketTypeRegister      TicketType = "register"
    TicketTypeLogin         TicketType = "login"
    TicketTypeResetPassword TicketType = "reset_password"
    TicketTypeOAuthBind     TicketType = "oauth_bind"
)

type TicketStatus string

const (
    TicketStatusPending  TicketStatus = "pending"
    TicketStatusVerified TicketStatus = "verified"
    TicketStatusUsed     TicketStatus = "used"
    TicketStatusExpired  TicketStatus = "expired"
)

type AdminRole string

const (
    AdminRoleAdmin      AdminRole = "admin"
    AdminRoleSuperAdmin AdminRole = "super_admin"
)

// ==================== 模型定义 ====================

// User 用户主表
type User struct {
    ID           int64      `gorm:"column:id;primaryKey;autoIncrement" json:"-"`
    UID          string     `gorm:"column:uid;type:varchar(255);uniqueIndex;not null" json:"uid"`
    Email        string     `gorm:"column:email;type:varchar(255);uniqueIndex;not null" json:"email"`
    PasswordHash string     `gorm:"column:password_hash;type:varchar(255)" json:"-"` // SHA-512 hex (128位)，与老后端完全一致
    Status       UserStatus `gorm:"column:status;type:user_status;not null;default:'active'" json:"status"`
    CreatedAt    time.Time  `gorm:"column:created_at;type:timestamptz;not null;default:now()" json:"created_at"`
    UpdatedAt    time.Time  `gorm:"column:updated_at;type:timestamptz;not null;default:now()" json:"updated_at"`

    // 关联
    Profile      *UserProfile   `gorm:"foreignKey:UserID;references:ID" json:"profile,omitempty"`
    OAuths       []UserOAuth    `gorm:"foreignKey:UserID;references:ID" json:"oauths,omitempty"`
    CareerRecords []CareerRecord `gorm:"foreignKey:UserID;references:ID" json:"career_records,omitempty"`
    Admin        *Admin         `gorm:"foreignKey:UserID;references:ID" json:"admin,omitempty"`
}

func (User) TableName() string {
    return "users"
}

// UserProfile 用户资料表
type UserProfile struct {
    ID        int64     `gorm:"column:id;primaryKey;autoIncrement" json:"-"`
    UserID    int64     `gorm:"column:user_id;type:bigint;uniqueIndex;not null" json:"-"`
    Nickname  string    `gorm:"column:nickname;type:varchar(255);not null" json:"nickname"`
    OrgID     int16     `gorm:"column:org_id;type:smallint;not null;default:-1" json:"org_id"`
    Bio       string    `gorm:"column:bio;type:text" json:"bio,omitempty"`
    Avatar    string    `gorm:"column:avatar;type:varchar(255)" json:"avatar,omitempty"`
    Link      JSONB     `gorm:"column:link;type:jsonb;default:'[]'" json:"link,omitempty"`
    Badge     JSONB     `gorm:"column:badge;type:jsonb;default:'[]'" json:"badge,omitempty"`
    Hide      JSONB     `gorm:"column:hide;type:jsonb;default:'[]'" json:"hide,omitempty"`
    CreatedAt time.Time `gorm:"column:created_at;type:timestamptz;not null;default:now()" json:"created_at"`
    UpdatedAt time.Time `gorm:"column:updated_at;type:timestamptz;not null;default:now()" json:"updated_at"`

    // 关联
    User         *User         `gorm:"foreignKey:UserID;references:ID" json:"user,omitempty"`
    Organization *Organization `gorm:"foreignKey:OrgID;references:ID" json:"organization,omitempty"`
}

func (UserProfile) TableName() string {
    return "user_profiles"
}

// Organization 组织架构表
type Organization struct {
    ID  int16  `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
    Dep string `gorm:"column:dep;type:varchar(255);not null" json:"dep"`
    Org string `gorm:"column:org;type:varchar(255)" json:"org,omitempty"`
}

func (Organization) TableName() string {
    return "organizations"
}

// CareerRecord 生涯记录表
type CareerRecord struct {
    ID        int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
    UserID    int64     `gorm:"column:user_id;type:bigint;not null;index" json:"-"`
    OrgID     int16     `gorm:"column:org_id;type:smallint;not null" json:"org_id"`
    Grade     int16     `gorm:"column:grade;type:smallint;not null" json:"grade"`
    Position  string    `gorm:"column:position;type:varchar(20)" json:"position,omitempty"`
    IsDeleted bool      `gorm:"column:is_deleted;type:boolean;not null;default:false" json:"is_deleted"`
    CreatedAt time.Time `gorm:"column:created_at;type:timestamptz;not null;default:now()" json:"created_at"`

    // 关联
    User         *User         `gorm:"foreignKey:UserID;references:ID" json:"user,omitempty"`
    Organization *Organization `gorm:"foreignKey:OrgID;references:ID" json:"organization,omitempty"`
}

func (CareerRecord) TableName() string {
    return "career_records"
}

// UserOAuth OAuth 绑定表
type UserOAuth struct {
    ID               int64         `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
    UserID           int64         `gorm:"column:user_id;type:bigint;not null;index" json:"-"`
    Provider         OAuthProvider `gorm:"column:provider;type:oauth_provider;not null" json:"provider"`
    ProviderUserID   string        `gorm:"column:provider_user_id;type:varchar(255);not null" json:"provider_user_id"`
    ProviderEmail    string        `gorm:"column:provider_email;type:varchar(255)" json:"provider_email,omitempty"`
    ProviderName     string        `gorm:"column:provider_name;type:varchar(255)" json:"provider_name,omitempty"`
    ProviderAvatar   string        `gorm:"column:provider_avatar;type:varchar(255)" json:"provider_avatar,omitempty"`
    AccessToken      string        `gorm:"column:access_token;type:text" json:"-"`
    RefreshToken     string        `gorm:"column:refresh_token;type:text" json:"-"`
    TokenExpiresAt   *time.Time    `gorm:"column:token_expires_at;type:timestamptz" json:"token_expires_at,omitempty"`
    RawData          JSONB         `gorm:"column:raw_data;type:jsonb;default:'{}'" json:"-"`
    CreatedAt        time.Time     `gorm:"column:created_at;type:timestamptz;not null;default:now()" json:"created_at"`
    UpdatedAt        time.Time     `gorm:"column:updated_at;type:timestamptz;not null;default:now()" json:"updated_at"`

    // 关联
    User *User `gorm:"foreignKey:UserID;references:ID" json:"user,omitempty"`
}

func (UserOAuth) TableName() string {
    return "user_oauths"
}

// Admin 管理员表
type Admin struct {
    ID        int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
    UserID    int64     `gorm:"column:user_id;type:bigint;uniqueIndex;not null" json:"-"`
    Role      AdminRole `gorm:"column:role;type:admin_role;not null;default:'admin'" json:"role"`
    CreatedAt time.Time `gorm:"column:created_at;type:timestamptz;not null;default:now()" json:"created_at"`

    // 关联
    User *User `gorm:"foreignKey:UserID;references:ID" json:"user,omitempty"`
}

func (Admin) TableName() string {
    return "admins"
}

// Ticket Ticket 审计表
type Ticket struct {
    ID        uuid.UUID     `gorm:"column:id;type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    Ticket    string        `gorm:"column:ticket;type:varchar(255);uniqueIndex;not null" json:"ticket"`
    Type      TicketType    `gorm:"column:type;type:ticket_type;not null" json:"type"`
    UserID    *int64        `gorm:"column:user_id;type:bigint;index" json:"user_id,omitempty"`
    Email     string        `gorm:"column:email;type:varchar(255);not null;index" json:"email"`
    Status    TicketStatus  `gorm:"column:status;type:ticket_status;not null;default:'pending'" json:"status"`
    ExpiresAt time.Time     `gorm:"column:expires_at;type:timestamptz;not null;index" json:"expires_at"`
    UsedAt    *time.Time    `gorm:"column:used_at;type:timestamptz" json:"used_at,omitempty"`
    CreatedAt time.Time     `gorm:"column:created_at;type:timestamptz;not null;default:now()" json:"created_at"`

    // 关联
    User *User `gorm:"foreignKey:UserID;references:ID" json:"user,omitempty"`
}

func (Ticket) TableName() string {
    return "tickets"
}

// ==================== 辅助类型 ====================

// JSONB 用于 GORM 的 jsonb 字段
type JSONB struct {
    Data interface{}
}

// Scan 实现 sql.Scanner 接口
func (j *JSONB) Scan(value interface{}) error {
    // 由 GORM 自动处理
    return nil
}

// Value 实现 driver.Valuer 接口
func (j JSONB) Value() (interface{}, error) {
    // 由 GORM 自动处理
    return j.Data, nil
}
```

### 6.1 GORM AutoMigrate 配置

```go
package infra

import (
    "sast-link-backend-v2/internal/domain"

    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "gorm.io/gorm/logger"
)

func NewDB(dsn string) (*gorm.DB, error) {
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
        Logger: logger.Default.LogMode(logger.Silent),
    })
    if err != nil {
        return nil, err
    }

    // 注册枚举类型（AutoMigrate 不会自动创建 ENUM，需手动或通过迁移工具）
    // 建议使用 golang-migrate 管理 Schema，而非 AutoMigrate

    // 如使用 AutoMigrate（仅开发环境）：
    // db.AutoMigrate(
    //     &domain.User{},
    //     &domain.UserProfile{},
    //     &domain.Organization{},
    //     &domain.CareerRecord{},
    //     &domain.UserOAuth{},
    //     &domain.Admin{},
    //     &domain.Ticket{},
    // )

    return db, nil
}
```

**重要**：生产环境必须使用 golang-migrate 管理 Schema 变更，禁止使用 `AutoMigrate`。

---

## 7. 附录

### 7.1 密码哈希说明

`users.password_hash` 字段统一使用 SHA-512 无盐哈希：

- 格式：128 位十六进制字符串（64 个 hex 字符）
- 算法：`crypto/sha512.Sum512(password) + hex.EncodeToString`
- 与老后端完全一致，不做任何迁移或转换

登录时验证逻辑：

```go
func VerifyPassword(password, hash string) bool {
    if len(hash) != 128 {
        return false
    }
    computed := sha512.Sum512([]byte(password))
    return subtle.ConstantTimeCompare([]byte(hash), []byte(hex.EncodeToString(computed[:]))) == 1
}
```

### 7.2 老 Schema 保留字问题

老 Schema 中 `"user"` 和 `"admin"` 表名使用 PostgreSQL 保留字，需用双引号包裹。新 Schema 统一改为复数形式 `users` / `admins`，避免此问题。

### 7.3 迁移检查清单

- [ ] 生产数据库已完整备份（pg_dump + 物理备份）
- [ ] 备份已在测试环境验证可恢复
- [ ] 迁移脚本已在测试环境完整执行并通过验证
- [ ] 应用层所有关键流程已在测试环境验证
- [ ] 维护窗口已通知用户
- [ ] 回滚方案已确认可行
- [ ] 迁移团队值班安排已确认
- [ ] 监控和告警已配置

---

*文档结束*
