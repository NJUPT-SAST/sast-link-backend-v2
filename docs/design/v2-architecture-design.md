# SAST Link Backend V2 架构设计文档

> 状态：已确认，s3 决策已融入
> 日期：2026-05-19
> 版本：v1.1

---

## 1. 设计目标

1. **API 兼容**：V1 版本完全兼容老后端 17+5 个 API 端点，确保 sast-link-next 前端零改动接入
2. **安全修复**：彻底消除老项目所有 P0/P1 安全漏洞
3. **飞书解耦**：保留飞书 OAuth 登录，但 SMTP 邮件和 Bot 通知必须可配置切换
4. **数据库可用**：老数据可通过迁移脚本导入新 schema，或新系统直接兼容老 schema
5. **可扩展**：多认证源（飞书/GitHub/微软/QQ）通过统一接口支持，未来新增 provider 无需改核心代码
6. **可测试**：全局依赖改为接口注入，支持单元测试并行执行

---

## 2. 技术选型

| 组件 | 选择 | 版本 | 理由 |
|------|------|------|------|
| 语言 | Go | 1.26.3 | 最新稳定版，支持 slog、iter 等新特性 |
| Web 框架 | Gin | v1.10+ | 团队熟悉，生态丰富，迁移成本低 |
| ORM | GORM | v1.25+ | 兼容老数据库最方便，支持灵活字段映射 |
| 数据库 | PostgreSQL | 15+ | 与老项目一致，无需额外运维成本 |
| 缓存 | Redis | 7+ | 与老项目一致 |
| 配置 | Viper | v1.19+ | 支持多格式、环境变量、热重载 |
| 日志 | slog | 标准库 | Go 官方推荐，结构化日志，性能优于 Logrus |
| JWT | golang-jwt/jwt/v5 | v5.2+ | 老项目在用，但正确使用 |
| 密码哈希 | SHA-512 无盐（与老后端完全一致） | crypto/sha512 | **已知安全债务**：SHA-512 无盐在离线破解场景下无防御能力，决策保留以兼容老数据。通过登录限流/验证码限流/全局限流/异常检测弥补在线攻击风险 |
| 数据库迁移 | golang-migrate | v4.18+ | 行业标配，支持回滚 |
| 邮件 | go-mail | v1.0+ | 现代 SMTP 客户端，支持 TLS/STARTTLS |
| 对象存储 | minio-go | v7 | 支持 S3 协议，兼容腾讯云 COS |
| 测试 | testify + httptest | 标准 | 单元测试 + HTTP 集成测试 |

---

## 3. 目录结构

```
sast-link-backend-v2/
├── cmd/
│   └── api/
│       └── main.go              # 应用入口
├── internal/
│   ├── config/                  # 配置加载与验证
│   │   ├── config.go
│   │   └── config_test.go
│   ├── domain/                  # 领域模型（无外部依赖）
│   │   ├── user.go
│   │   ├── profile.go
│   │   ├── oauth.go
│   │   ├── ticket.go
│   │   └── errors.go            # 业务错误码定义
│   ├── repository/              # 数据访问层（接口+实现）
│   │   ├── interfaces.go        # Repository 接口定义
│   │   ├── user_repo.go
│   │   ├── profile_repo.go
│   │   ├── oauth_repo.go
│   │   └── ticket_repo.go
│   ├── service/                 # 业务逻辑层
│   │   ├── user_service.go      # 注册/登录/密码管理
│   │   ├── profile_service.go   # 资料管理
│   │   ├── oauth_service.go     # OAuth 登录/绑定
│   │   ├── oauth2_server_service.go  # OAuth2 授权服务端（SSO）
│   │   └── email_service.go     # 邮件服务（抽象接口）
│   ├── handler/                 # HTTP Handler
│   │   ├── user.go
│   │   ├── profile.go
│   │   ├── oauth.go
│   │   └── oauth_server.go      # OAuth2 授权服务端点
│   ├── middleware/              # 中间件
│   │   ├── auth.go              # JWT 鉴权（正确实现）
│   │   ├── cors.go
│   │   ├── rate_limit.go        # 限流
│   │   ├── request_log.go       # 请求日志
│   │   └── recovery.go          # Panic 恢复
│   ├── auth/                    # 认证核心包
│   │   ├── jwt.go               # JWT 生成/解析/验证
│   │   ├── ticket.go            # Ticket 生成/验证
│   │   ├── password.go          # 密码哈希/验证
│   │   └── oauth/
│   │       ├── provider.go      # OAuth Provider 统一接口
│   │       ├── feishu.go        # 飞书实现
│   │       ├── github.go        # GitHub 实现
│   │       ├── microsoft.go     # 微软实现（预留）
│   │       └── qq.go            # QQ 实现（预留）
│   ├── pkg/                     # 内部共享工具
│   │   ├── response/            # 统一响应格式
│   │   ├── validator/           # 参数校验
│   │   └── email/               # SMTP 客户端封装
│   └── infra/                   # 基础设施初始化
│       ├── db.go                # PostgreSQL 连接
│       ├── redis.go             # Redis 连接
│       └── log.go               # slog 初始化
├── pkg/                         # 可复用公共包（未来可独立发布）
├── migrations/                  # 数据库迁移文件
│   ├── 000001_create_enums.up.sql
│   ├── 000001_create_enums.down.sql
│   ├── 000002_create_tables.up.sql
│   ├── 000002_create_tables.down.sql
│   ├── 000003_migrate_data.up.sql
│   ├── 000003_migrate_data.down.sql
│   └── 000004_seed_organizations.up.sql
├── scripts/
│   ├── migrate.sh               # 迁移脚本
│   └── seed.sh                  # 数据初始化
├── docker/
│   └── Dockerfile
├── docker-compose.yml
├── docs/
│   ├── design/                  # 设计文档
│   └── api/                     # API 文档
├── go.mod
├── go.sum
├── .env.example                 # 环境变量模板
└── Makefile                     # 常用命令
```

### 分层职责

| 层 | 职责 | 依赖方向 |
|----|------|---------|
| Handler | HTTP 请求/响应处理、参数绑定、调用 Service | → Service |
| Service | 业务逻辑编排、事务控制、调用 Repository | → Repository |
| Repository | 数据持久化，实现 domain 定义的接口 | → DB/Redis |
| Domain | 纯模型、常量、错误定义，无外部依赖 | ← 所有层 |
| Auth | 认证核心逻辑（JWT/Ticket/Password/OAuth） | → Domain |
| Middleware | 横切关注点（鉴权/限流/日志） | → Auth/Infra |

---

## 4. 数据库设计

### 4.1 设计原则

1. **修复老 schema 所有缺陷**：外键约束、类型统一、命名规范、索引齐全
2. **兼容老数据**：迁移脚本将老数据完整导入新 schema
3. **保留核心字段名**：前端依赖的 JSON 字段名保持不变
4. **使用时间戳统一**：所有时间字段使用 `TIMESTAMPTZ`

### 4.2 表结构

```sql
-- 枚举类型
CREATE TYPE user_status AS ENUM ('active', 'suspended', 'deleted');
CREATE TYPE oauth_provider AS ENUM ('feishu', 'github', 'microsoft', 'qq');
CREATE TYPE ticket_type AS ENUM ('register', 'login', 'reset_password', 'oauth_bind');
CREATE TYPE ticket_status AS ENUM ('pending', 'verified', 'used', 'expired');
CREATE TYPE admin_role AS ENUM ('admin', 'super_admin');

-- 用户主表（替代 "user"，避免 PostgreSQL 保留字）
CREATE TABLE users (
    id              BIGSERIAL PRIMARY KEY,
    uid             VARCHAR(255) UNIQUE NOT NULL,       -- 学号，如 B21010101
    email           VARCHAR(255) UNIQUE NOT NULL,       -- @njupt.edu.cn
    password_hash   VARCHAR(255),                       -- SHA-512 hex (128位), 与老后端完全一致, OAuth-only: NULL
    status          user_status NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_uid ON users(uid);

-- 用户资料表（替代 profile，合并冗余 email 字段）
CREATE TABLE user_profiles (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    nickname    VARCHAR(255) NOT NULL,
    org_id      SMALLINT NOT NULL DEFAULT -1,           -- -1 表示未分配
    bio         TEXT,
    avatar      VARCHAR(255),                           -- OSS URL
    link        JSONB DEFAULT '[]',                     -- 社交链接数组
    badge       JSONB DEFAULT '[]',                     -- 纪念卡
    hide        JSONB DEFAULT '[]',                     -- 隐藏字段
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id)
);

CREATE INDEX idx_user_profiles_user_id ON user_profiles(user_id);

-- 组织架构表（替代 organize）
CREATE TABLE organizations (
    id      SMALLSERIAL PRIMARY KEY,
    dep     VARCHAR(255) NOT NULL,  -- 部门
    org     VARCHAR(255)             -- 组/组织
);

-- 生涯记录表（替代 carrer_records，修复拼写和命名）
CREATE TABLE career_records (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      SMALLINT NOT NULL REFERENCES organizations(id),
    grade       SMALLINT NOT NULL,      -- 届数，如 2023
    position    VARCHAR(20),            -- 职位
    is_deleted  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_career_records_user_id ON career_records(user_id);
CREATE INDEX idx_career_records_org_grade ON career_records(org_id, grade);

-- OAuth 绑定表（替代 oauth2_info，修复 user_id 类型）
CREATE TABLE user_oauths (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider            oauth_provider NOT NULL,
    provider_user_id    VARCHAR(255) NOT NULL,
    provider_email      VARCHAR(255),
    provider_name       VARCHAR(255),
    provider_avatar     VARCHAR(255),
    access_token        TEXT,           -- 加密存储
    refresh_token       TEXT,           -- 加密存储
    token_expires_at    TIMESTAMPTZ,
    raw_data            JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX idx_user_oauths_user_id ON user_oauths(user_id);

-- 管理员表（修复 user_id 类型为 BIGINT）
CREATE TABLE admins (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    role        admin_role NOT NULL DEFAULT 'admin',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 新增：ticket 持久化表（用于追踪和审计，实际状态仍存 Redis）
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
```

### 4.3 与老 Schema 的映射关系

| 老表 | 新表 | 关键变更 |
|------|------|---------|
| `"user"` | `users` | 表名改为复数，加外键约束 |
| `profile` | `user_profiles` | 移除 email 字段，user_id 加外键 |
| `organize` | `organizations` | 无实质变更 |
| `carrer_records` | `career_records` | 修复拼写，position 改为 varchar(20) |
| `oauth2_info` | `user_oauths` | user_id 改为 BIGINT，支持多 provider |
| `admin` | `admins` | user_id 改为 BIGINT，加外键 |
| `oauth2_tokens` | 移除 | go-oauth2-pg 专用表，如保留 OAuth2 服务端则重建 |
| `oauth2_clients` | 移除 | go-oauth2-pg 专用表，如保留 OAuth2 服务端则重建 |
| — | `tickets` | 新增，用于 ticket 审计追踪 |

### 4.4 数据迁移策略

提供一次性迁移脚本，将老数据库数据导入新 schema：

```
老数据库 ──→ pg_dump ──→ 数据清洗脚本 ──→ 新 schema
```

清洗内容：
1. `admin.user_id` varchar → bigint 转换
2. `oauth2_info.user_id` varchar → 先查 users.uid 匹配，再写入 bigint user_id
3. `profile.email` → 丢弃，从 users.email 获取
4. `carrer_records.is_delete` → 重命名为 `is_deleted`
5. 删除 `user` 表中 `qq_id`、`lark_id`、`github_id`、`wechat_id` 字段（数据迁移到 user_oauths）

---

## 5. 认证系统设计

### 5.1 核心原则

1. **单 Token 模式**：与老后端完全一致，JWT 有效期 7 天
2. **Ticket 机制保留**：注册/登录/重置密码的多阶段验证流程不变
3. **登出即失效**：删除 Redis 白名单 `sastlink:token:{uid}`，并将 JWT jti 加入黑名单（双重保险）

### 5.2 Token 体系

| Token 类型 | 存储位置 | 有效期 | 用途 |
|-----------|---------|--------|------|
| Register-Ticket | Redis | 5 min | 注册流程阶段凭证 |
| Login-Ticket | Redis | 5 min | 登录流程阶段凭证 |
| ResetPwd-Ticket | Redis | 6 min | 密码重置流程阶段凭证 |
| OAuth-Ticket | Redis | 3 min | OAuth 绑定流程凭证 |
| Login-Token | Redis `sastlink:token:{uid}` + 客户端 localStorage | 7 days | API 鉴权 |

### 5.3 JWT 设计

```go
// Claims 结构
type Claims struct {
    jwt.RegisteredClaims
    UserID    int64  `json:"uid"`     // 用户 ID
    Username  string `json:"uname"`   // 学号
    Role      string `json:"role"`    // user | admin | super_admin
}
```

- **Signing Method**: HS256
- **Signing Key**: 256-bit 随机串，从环境变量 `JWT_SECRET_KEY` 读取
- **Issuer**: "sast-link"
- **Audience**: "sast-link-api"
- **传输方式**: `Token` header（与老后端一致）

### 5.4 Ticket 设计

```go
// Redis 键名规范
sastlink:ticket:{type}:{ticket_id}
// 如：sastlink:ticket:register:abc123

// 值结构（JSON）
{
  "email": "B21010101@njupt.edu.cn",
  "status": "pending",      // pending | verified | used
  "code": "S-12345",        // 验证码（仅 register/reset 需要）
  "expires_at": "2026-05-19T12:00:00Z"
}
```

### 5.5 OAuth Provider 统一接口

```go
// OAuthProvider 所有第三方登录必须实现此接口
type OAuthProvider interface {
    Name() string                                    // "feishu" | "github" | "microsoft" | "qq"
    AuthURL(state, redirectURI string) string        // 构建授权 URL
    Exchange(ctx context.Context, code string) (*OAuthUserInfo, error)  // 用 code 换用户信息
}

type OAuthUserInfo struct {
    ProviderUserID string            // 第三方系统用户唯一标识
    Email          string
    Name           string
    Avatar         string
    RawData        map[string]any    // 原始响应（存 raw_data 字段）
}
```

### 5.6 登录流程状态机

```
[OAuth 回调]
    │
    ▼
[检查 provider_user_id 是否已绑定]
    │
    ├─ 已绑定 ──→ [生成单 Token] ──→ [登录成功]
    │
    └─ 未绑定
           │
           ▼
    [检查 provider_email 是否匹配已有用户]
           │
           ├─ 匹配 ──→ [可选：自动绑定 / 提示绑定] ──→ [生成 Token]
           │
           └─ 不匹配
                  │
                  ▼
           [生成 OAuth-Ticket]
                  │
                  ▼
           [前端跳转 /login?oauthTicket=xxx]
                  │
                  ▼
           [用户输入已有账号密码]
                  │
                  ▼
           [验证密码正确]
                  │
                  ▼
           [创建 user_oauths 记录]
                  │
                  ▼
           [生成单 Token]
```

---

## 6. API 设计

### 6.1 保留端点（与老项目完全一致）

所有端点路径、方法、请求/响应格式与老项目保持一致，仅修复内部实现。

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/api/v1/verify/account` | - | 验证账号，返回 ticket |
| GET | `/api/v1/sendEmail` | Ticket | 发送验证码邮件 |
| POST | `/api/v1/verify/captcha` | Ticket | 验证邮箱验证码 |
| POST | `/api/v1/user/register` | Register-Ticket | 用户注册 |
| POST | `/api/v1/user/login` | Login-Ticket | 用户登录 |
| POST | `/api/v1/user/logout` | Token | 用户登出 |
| POST | `/api/v1/user/changePassword` | Token | 修改密码 |
| POST | `/api/v1/user/resetPassword` | ResetPwd-Ticket | 重置密码 |
| GET | `/api/v1/user/info` | Token | 获取用户基本信息 |
| GET | `/api/v1/login/lark` | - | 飞书登录入口 |
| GET | `/api/v1/login/lark/callback` | - | 飞书回调 |
| GET | `/api/v1/login/github` | - | GitHub 登录入口 |
| GET | `/api/v1/login/github/callback` | - | GitHub 回调 |
| GET | `/api/v1/profile/getProfile` | Token | 获取用户资料 |
| POST | `/api/v1/profile/changeProfile` | Token | 修改用户资料 |
| POST | `/api/v1/profile/uploadAvatar` | Token | 上传头像 |
| GET | `/api/v1/profile/bindStatus` | Token | 获取 OAuth 绑定状态 |

### 6.2 OAuth2 授权服务端端点（V1 实现，对外提供 SSO）

**s3 决策**：OAuth2 服务端有外部系统依赖，V1 实现。

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/api/v1/oauth2/authorize` | - | 授权码请求（用户浏览器重定向） |
| POST | `/api/v1/oauth2/token` | Client 凭证 | 用授权码换 Access/Refresh Token |
| POST | `/api/v1/oauth2/refresh` | - | 用 Refresh Token 换新的 Token 对 |
| POST | `/api/v1/oauth2/create-client` | Login-Token | 注册 OAuth 客户端（仅管理员） |
| POST | `/api/v1/oauth2/revoke` | - | 撤销 Token |
| GET | `/api/v1/oauth2/userinfo` | Bearer | 获取用户基本信息 |

**实现方案**：使用 `go-oauth2/oauth2`（老后端已用，代码复用度高），修复已知漏洞（Token TTL 不一致、Cookie MaxAge 不匹配等）。Storage 接口接 PostgreSQL + Redis，与现有基础设施复用。

**注意**：OAuth2 服务端的 Access/Refresh Token 独立于 Login-Token（后者是用户自用，前者是对外授权）。

### 6.3 新增端点（V2 引入）

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| POST | `/api/v1/user/bindOauth` | Token | 主动绑定 OAuth 账号 |
| POST | `/api/v1/user/unbindOauth` | Token | 解绑 OAuth 账号（需保留至少一种登录方式） |

---

## 7. 邮件服务抽象

### 7.1 EmailProvider 接口

```go
type EmailProvider interface {
    SendVerificationEmail(to, code string) error
    SendPasswordResetEmail(to, code string) error
}
```

### 7.2 SMTP 实现

```go
type SMTPProvider struct {
    Host     string
    Port     int
    Username string
    Password string
    From     string
    UseTLS   bool
}
```

### 7.3 配置示例

```toml
[email]
provider = "smtp"
host = "smtp.example.com"
port = 587
username = "${SMTP_USERNAME}"
password = "${SMTP_PASSWORD}"
from = "noreply@sast.fun"
use_tls = true
```

**邮件解耦策略**：通过 `EmailProvider` 接口完全抽象 SMTP 细节。默认不绑定任何特定服务商，通过环境变量/配置文件注入 SMTP 参数。飞书 SMTP 可作为其中一种配置选项，但不作为默认值。Bot 通知独立配置，可选启用。

---

## 8. 关键模块设计

### 8.1 统一响应格式

与老前端完全兼容：

```go
type Response struct {
    Success bool        `json:"Success"`
    Data    any         `json:"Data,omitempty"`
    ErrCode int         `json:"ErrCode,omitempty"`
    ErrMsg  string      `json:"ErrMsg,omitempty"`
}
```

错误码体系（**保留老后端全部 5 位错误码，不引入新码**）：

| 错误码 | 含义 | 使用场景 |
|--------|------|----------|
| 10001 | 请求参数错误 | 参数缺失/格式错误 |
| 10002 | 用户名错误 | - |
| 10003 | 密码错误 | 密码格式不符 |
| 10004 | 密码为空 | - |
| 10005 | 登录失败 | - |
| 10007 | 重复注册 | 账号已存在 |
| 10010 | OAuth用户未注册或未绑定 | - |
| 10011 | 用户不存在 | - |
| 20002 | Token已超时 | - |
| 20003 | Token生成失败 | - |
| 20004 | Token错误 | - |
| 20006 | Token解析失败 | - |
| 20007 | Ticket不正确 | - |
| 20008 | Ticket不存在 | - |
| 30001 | 发送邮件失败 | - |
| 30002 | 验证码错误 | - |
| 30003 | 邮箱格式错误 | - |
| 40001 | 验证账户失败 | - |
| 40002 | 验证账户密码失败 | - |
| 50000 | 未知错误 | 内部错误 |
| 60001 | 客户端错误 | - |
| 60002 | access_token错误 | - |
| 60003 | refresh_token错误 | - |
| 70003 | 注册失败（阶段错误） | - |
| 70004 | 重置密码失败 | - |
| 80000 | 用户profile不存在 | - |
| 80001 | 组织填写错误 | - |
| 80002 | 填写隐藏信息不合法 | - |
| 90000 | 发送审核通知信息失败 | - |
| 90001 | 处理冻结图片失败 | - |
| 90002 | 图片URL地址错误 | - |

成功响应：`ErrCode = 200`

### 8.2 请求日志与可观测性

- **请求日志**：slog 结构化日志，记录方法、路径、状态码、耗时、trace_id
- **敏感信息脱敏**：Authorization、Token、Cookie、Password 字段值替换为 `[REDACTED]`
- **Trace ID**：每个请求生成 UUID trace_id，贯穿请求生命周期，返回给前端便于排查

### 8.3 限流策略

| 端点 | 限制 |
|------|------|
| `/api/v1/sendEmail` | 3 次/分钟/账号 |
| `/api/v1/verify/captcha` | 5 次/分钟/IP |
| `/api/v1/user/login` | 5 次/分钟/账号 |
| `/api/v1/user/register` | 3 次/小时/IP |
| 全局 | 100 次/分钟/IP |

---

## 9. 部署方案

### 9.1 Docker Compose

```yaml
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: sastlink
      POSTGRES_USER: sastlink
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sastlink"]

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redisdata:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]

  api:
    build:
      context: .
      dockerfile: docker/Dockerfile
    environment:
      APP_ENV: production
      DATABASE_URL: postgres://sastlink:${POSTGRES_PASSWORD}@postgres:5432/sastlink?sslmode=disable
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379/0
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}
    depends_on:
      postgres: condition: service_healthy
      redis: condition: service_healthy
    ports:
      - "8080:8080"

volumes:
  pgdata:
  redisdata:
```

### 9.2 健康检查

```
GET /ping          →  "pong"  (Liveness)
GET /health        →  { "status": "ok", "db": "ok", "redis": "ok" }  (Readiness)
```

---

## 10. 测试策略

| 测试类型 | 范围 | 目标 |
|----------|------|------|
| 单元测试 | Service、Auth、Domain | 业务逻辑覆盖率 100% |
| 集成测试 | Repository + 测试数据库 | 数据库操作正确性 |
| HTTP 测试 | Handler + httptest | API 契约兼容性 |
| 冒烟测试 | 端到端关键链路 | 部署后验证 |

---

## 11. s3 决策记录

| # | 决策项 | s3 选择 | 文档位置 |
|---|--------|---------|----------|
| 1 | 数据库兼容策略 | 新 schema + 一次性迁移脚本（不能弄坏生产） | 本文档 §4.3 |
| 2 | Go 版本 | 1.26.3 | 本文档 §2 |
| 3 | QQ 登录 | 保留，纳入 V1 | 本文档 §4.2, §5.5 |
| 4 | 邮箱服务 | 不默认飞书，支持任意 SMTP 配置 | 本文档 §7 |
| 5 | 密码 SHA-512 | **统一 SHA-512，完全不动**，所有用户（新老）均使用相同哈希逻辑，通过限流和复杂度策略弥补安全性 | 本文档 §2, §5.2 |
| 6 | Token 机制 | 单 Token 7 天，与老后端完全一致，不引入 Access/Refresh 双 Token | 本文档 §5.2 |
| 7 | RBAC | V1 引入基础版（user/admin/super_admin） | 本文档 §4.2 |
| 8 | OAuth2 服务端 | V1 实现，对外提供 SSO（使用 go-oauth2/oauth2） | 本文档 §6.2 |

## 12. 文档清单

| 文档 | 路径 | 状态 |
|------|------|------|
| 架构总览 | `docs/design/v2-architecture-design.md` | 已完成 |
| 数据库设计 | `docs/design/database-design.md` | 已完成 v1.0 |
| API 详细设计 | `docs/design/api-design.md` | 已完成 v1.3 |
| 认证系统与 RBAC | `docs/design/auth-rbac-design.md` | 已完成 v1.1 |
| 部署与配置方案 | `docs/design/deployment-design.md` | 已完成 v1.0 |

---

*全部设计文档已完成，进入编码阶段。*
