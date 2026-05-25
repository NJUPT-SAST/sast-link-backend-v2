# SAST Link Backend V2 — 产品需求文档 (PRD)

| 项目 | 内容 |
|------|------|
| 产品名称 | SAST Link Backend V2 |
| 版本 | v1.2 |
| 日期 | 2026-05-25 |

---

## 1. 背景与问题陈述

### 1.1 现状

SAST Link 是南京邮电大学校大学生科学技术协会（SAST）的统一身份认证与人员管理系统，目前运行在老后端（Go + Gin，代号 V1）上。老后端存在以下问题：

- **代码质量**：无测试覆盖，错误处理混乱
- **可维护性**：缺少分层架构，业务逻辑与数据访问耦合严重
- **扩展性**：OAuth2 服务端未实现，第三方登录仅支持 GitHub/飞书，QQ 登录预留但未填充
- **运维**：缺少统一日志、监控、配置管理

本项目（V2）基于一个初始项目 scaffold（Go + Gin + GORM + PostgreSQL，含基础分层架构与 CI 流水线）进行开发，直接在此基础上迭代重构，逐步实现全部功能。

### 1.2 目标

对 SAST Link 后端进行全面重构，引入 OAuth 2.1 标准作为认证授权体系，提升代码质量、可维护性和安全性。

### 1.3 范围

- 账号注册/登录/登出/改密/重置密码
- 邮箱验证码
- 用户资料管理（查看/编辑/头像上传）
- GitHub / 飞书 OAuth 主动绑定/解绑 + 登录
- OAuth 首次登录注册补全教育邮箱
- 限流与防刷
- 操作日志 + 健康检查
- 头像内容审核（腾讯云 COS）
- OAuth2 授权服务端（Auth 2.1 标准）
- 管理后台
- 审计日志

---

### 1.4 非目标（Non-goals）

以下功能/策略**不在 V2 范围内**：

- **API 契约**：不保证前端零改动，仅在性能或安全需求迫使时修改响应格式，需经技术评审
- **认证协议**：不限制为 JWT HS256，全面引入 OAuth 2.1 标准
- **管理后台**：第一版不实现细粒度 RBAC，仅基础成员管理
- **历史数据**：不迁移老用户历史操作日志，V2 从零开始记录
- **OAuth2 模式**：不限于授权码模式，按 OAuth 2.1 标准实现
- **QQ 登录**：已舍去

---

## 2. 目标用户

| 用户类型 | 描述 | 核心诉求 |
|----------|------|----------|
| **SAST 成员** | 南邮 SAST 的学生成员 | 快速注册、管理个人资料、使用统一身份登录各 SAST 项目 |
| **外部开发者** | 其他 SAST 项目的前后端开发者 | 通过 OAuth2 接入 SAST 账号体系（V2） |
| **前端团队** | SAST Link 前端维护者 | 稳定、文档清晰的 API |
| **运维人员** | 系统维护者 | 可监控、易部署、有问题能定位 |

---

## 4. 产品目标与成功指标

| 目标 | 指标 | 目标值 |
|------|------|--------|
| API 稳定性 | 单元测试覆盖率 | ≥ 80% 不卡门禁 |
| 注册成功率 | 注册完成率 | ≥ 95% |
| 登录性能 | P99 登录响应时间 | ≤ 200ms |
| 系统可用性 | 服务可用时间 | ≥ 99.9% |
| 代码质量 | golangci-lint 全绿 | 0 警告 |
| CI 质量 | 安全扫描（gosec + govulncheck） | 0 高危漏洞 |
| CI 质量 | 构建验证 + race detector | 全绿 |
| CI 质量 | 依赖检查（go mod tidy） | 无未提交变更 |

---

## 5. 功能需求

### 5.1 功能与端点列表

| ID | 功能 | 用户故事 | 端点与说明 |
|----|------|----------|----------|
| F-1 | 账号验证 | US-1, US-2 | GET `/verify/account` 验证账号是否存在/可用，返回对应 Ticket |
| F-2 | 验证码校验 | US-1 | POST `/verify/captcha` 校验邮箱验证码，验证码格式 `S-XXXXX`（5位） |
| F-3 | 发送验证邮件 | US-1 | POST `/sendEmail` 发送含验证码的邮件，限流 2 次/分钟 |
| F-4 | 用户注册 | US-1 | POST `/user/register` 完成注册，密码 6-64 位，含字母+数字 |
| F-5 | 用户登录 | US-2 | POST `/user/login` 返回 Access Token + Refresh Token |
| F-6 | 用户登出 | US-2 | POST `/user/logout` 使当前 Token 失效 |
| F-7 | 修改密码 | US-2 | POST `/user/changePassword` 验证旧密码后修改 |
| F-8 | 重置密码 | US-1 | POST `/user/resetPassword` 通过 Ticket 重置密码 |
| F-9 | 获取用户信息 | US-2 | GET `/user/info` 返回 email + userId |
| F-10 | 获取用户资料 | US-4, US-5 | GET `/profile/getProfile` 返回完整资料 |
| F-11 | 修改用户资料 | US-4 | POST `/profile/changeProfile` 修改昵称/组织/简介/链接/隐私 |
| F-12 | 上传头像 | US-4 | POST `/profile/uploadAvatar` 返回字符串路径 |
| F-13 | GitHub 登录 | US-3 | GET `/login/github` + `/login/github/callback` |
| F-14 | 飞书登录 | US-3 | GET `/login/lark` + `/login/lark/callback` |
| F-15 | OAuth 绑定状态 | US-3 | GET `/profile/bindStatus` 返回已绑定的 OAuth 列表 |
| F-16 | GitHub 绑定 | US-3 | GET `/profile/bind/github` 发起绑定（需登录态），302 重定向到 GitHub 授权页 |
| F-17 | GitHub 绑定回调 | US-3 | GET `/profile/bind/github/callback` 绑定回调，成功后返回绑定结果 |
| F-18 | 飞书绑定 | US-3 | GET `/profile/bind/lark` 发起绑定（需登录态），302 重定向到飞书授权页 |
| F-19 | 飞书绑定回调 | US-3 | GET `/profile/bind/lark/callback` 绑定回调，成功后返回绑定结果 |
| F-20 | 解除第三方绑定 | US-3 | POST `/profile/unbind` 解除指定 provider 绑定，邮箱不可解绑 |
| F-21 | OAuth 注册补全 | US-3 | POST `/user/oauthRegister` OAuth 首次登录后补全注册（绑定邮箱+验证码+设密码） |
| F-22 | 限流与防刷 | — | 中间件层实现，对登录、注册、发邮件等接口增加限流，无独立端点 |
| F-23 | 操作日志 | — | 记录关键操作（登录、密码修改、资料变更），无独立查询端点（V2 第一版） |
| F-24 | 健康检查 | — | GET `/ping` 或 GET `/health` 健康检查端点 |
| F-25 | 头像内容审核 | US-4 | F-12 上传头像的后置流程，触发腾讯云 COS 内容审核，无独立端点 |
| F-26a | OAuth2 授权端点 | — | GET `/oauth2/authorize` 授权端点，PKCE-S256 强制 |
| F-26b | OAuth2 Token 端点 | — | POST `/oauth2/token`  Token 端点，支持 authorization_code 和 refresh_token grant_type |
| F-26c | OAuth2 撤销端点 | — | POST `/oauth2/revoke`  撤销端点，支持 Access/Refresh Token 撤销 |
| F-26d | OAuth2 自省端点 | — | POST `/oauth2/introspect`  Token 自省端点 |
| F-26e | JWKS 端点 | — | GET `/.well-known/jwks.json` 公钥集暴露端点 |
| F-27 | OAuth2 客户端注册 | — | POST `/oauth2/register` 动态注册 OAuth 客户端 |
| F-28 | 管理后台 | — | 待详细设计（成员管理、组织管理、徽章管理、成就系统） |
| F-29 | 审计日志 | — | 待详细设计，完整的操作审计 |
| F-30 | 发起邮箱绑定 | US-2 | POST `/profile/bindEmail` 发送验证码到指定邮箱，限流 2 次/分钟 |
| F-31 | 验证并完成邮箱绑定 | US-2 | POST `/profile/verifyBindEmail` 验证验证码后完成绑定，上限 2 个 |
| F-32 | 发起邮箱解绑 | US-2 | POST `/profile/unbindEmail` 发送解绑验证码到指定邮箱，限流 2 次/分钟 |
| F-33 | 确认解绑邮箱 | US-2 | POST `/profile/confirmUnbindEmail` 验证验证码后完成解绑，1 分钟冷却期 |
| F-34 | 获取已绑定邮箱 | US-2 | GET `/profile/emails` 返回已绑定的第三方邮箱列表 |
| F-35 | OAuth 绑定已有账号 | US-3 | POST `/user/oauthBindExisting` OAuth 注册时邮箱已被占用，将 OAuth 账号绑定到已有用户（无需登录态，需密码验证） |

---

## 6. 非功能需求

### 6.1 性能

- API P99 响应时间 ≤ 200ms
- 数据库查询需有索引，慢查询日志阈值 100ms
- Redis 操作 P99 ≤ 10ms

### 6.2 安全

- 密码存储：PBKDF2-HMAC-SHA512，100,000 次迭代，32 字节随机 salt，salt 与哈希结果一并存储（格式：`$pbkdf2-sha512$iter$salt$hash`）。老用户原有 SHA512 格式密码在登录验证通过后自动重哈希为新格式
- Token：Access Token 使用 RS256 签名（15 分钟），Refresh Token 为 opaque token（7 天），OAuth 2.1 标准
- 设备上限：Redis 中每个用户最多保留 5 个有效 Token Family，新登录淘汰最旧设备
- Token 失效策略：修改密码 / 重置密码时递增 `token_version`，使所有现有 Token 失效；登出仅清除当前设备 Token
- Refresh Token 轮转：每次刷新发放新 Refresh Token，旧 Token 立即失效；检测到旧 Token 重放时撤销整个 Token Family
- PKCE：所有客户端（含第一方）强制使用 PKCE-S256
- 验证码：Redis 存储，有效期因场景而异（Register-Ticket 5 分钟、Login-Ticket 5 分钟、ResetPwd-Ticket 6 分钟、OAuth-Ticket 3 分钟、BindEmail-Ticket 5 分钟、UnbindEmail-Ticket 5 分钟）
- HTTPS 强制
- SQL 注入防护：使用参数化查询（ORM）
- XSS 防护：API 返回纯 JSON，不做 HTML 渲染

**限流策略**：

| 接口 | 限流规则 | 触发后行为 |
|------|----------|------------|
| 登录 `/user/login` | 5 次/分钟/IP | 锁定 15 分钟，返回 `10008` |
| 注册 `/user/register` | 3 次/分钟/IP | 返回 `10008` |
| 发送邮件（所有场景） | 2 次/分钟/邮箱 | 返回 `10008` |
| 验证码校验 | 10 次/分钟/IP | 返回 `10008` |
| 修改密码 `/user/changePassword` | 3 次/小时/账号 | 返回 `10008` |
| 重置密码 `/user/resetPassword` | 3 次/小时/账号 | 返回 `10008` |
| 头像上传 `/profile/uploadAvatar` | 10 次/分钟/用户 | 返回 `10008` |
| 邮箱解绑 `/profile/unbindEmail` | 2 次/分钟/邮箱 | 返回 `10008` |

**RS256 私钥管理**：

- **密钥生成**：`openssl genrsa -out private.pem 2048`，对应公钥 `openssl rsa -in private.pem -pubout -out public.pem`
- **私钥存储**：生产环境使用环境变量或 Secret Manager 注入，不提交到代码仓库；开发环境使用 `.env` 文件
- **公钥分发**：通过 `GET /.well-known/jwks.json` 暴露 JWK Set，支持资源服务器独立验签
- **密钥轮换**：
  - 支持多公钥同时存在，每个 key 带 `kid`（Key ID）标识
  - 轮换周期 90 天，新旧密钥重叠期 7 天（新旧 Token 均可验签）
  - 轮换时只更新私钥和 JWKS 中的公钥列表，不影响已签发 Token 的合法性

### 6.3 CI 与测试策略

**基础检查**：
- golangci-lint v2.12 + gofmt + go vet
- race detector + build verification
- gosec + govulncheck（安全扫描）
- go mod tidy 检查

**测试分层**：

| 层级 | 标签 | 依赖 | 覆盖范围 | 执行时间 |
|------|------|------|----------|----------|
| 单元测试 | `!integration`（默认） | miniredis + mock | usecase、handler、简单 repo 操作 | 秒级 |
| 集成测试 | `//go:build integration` | testcontainers（真实 Postgres + Redis） | repository 层、复杂查询、migration | 分钟级 |

**代码改动**：
- 新增依赖：testcontainers-go + modules/postgres + modules/redis
- 新增文件：`internal/repository/*_integration_test.go`
- 现有测试保持不变，继续用 miniredis 做单元测试

### 6.4 可靠性

- graceful shutdown：处理完当前请求或等待最多 30 秒后退出
- 数据库连接池：最大 20 连接，连接超时 5 秒
- Redis 断连自动重连

### 6.5 可观测性

- 结构化日志（JSON 格式）
- 关键接口请求量/延迟/错误率指标
- 慢查询告警

### 6.6 兼容性

- UserId 保持 `string` 类型
- Profile 返回 `dep` + `org` 字符串（通过 `org_id` 联表查询）

---

## 7. 技术架构

### 7.1 技术栈

| 层 | 技术 | 版本 |
|----|------|------|
| 语言 | Go | 1.26.3 |
| Web 框架 | Gin | v1.12.0 |
| ORM | GORM | v1.31.1 |
| 数据库 | PostgreSQL | 15+（生产直连已有部署，开发用 Docker） |
| 缓存 | Redis | 7+ |
| 对象存储 | 腾讯云 COS | — |
| 邮件 | SMTP | — |
| 密码哈希 | PBKDF2-HMAC-SHA512 | 100,000 迭代，32B 随机 salt |
| 认证授权 | OAuth 2.1 + RS256 | — |
| 安全扫描 | gosec + govulncheck | — |
| 集成测试 | testcontainers-go | — |

### 7.2 分层架构

```
┌─────────────┐
│   Handler   │  ← HTTP 请求处理、参数校验
├─────────────┤
│   Service   │  ← 业务逻辑
├─────────────┤
│ Repository  │  ← 数据访问（GORM）
├─────────────┤
│   Infra     │  ← Redis、COS、SMTP 等外部服务
└─────────────┘
```

### 7.3 统一响应格式

所有 API 返回统一结构：

```json
{
  "Success": true,
  "ErrCode": 200,
  "ErrMsg": "",
  "Data": { ... }
}
```

成功时 `Success = true, ErrCode = 200`；失败时 `Success = false, ErrCode = 5 位错误码`。

HTTP 状态码统一 200，业务状态通过 `ErrCode` 表达。

> **例外**：OAuth 2.1 端点（`/oauth2/*` 及 `/.well-known/*`）使用标准响应格式，不遵循本统一结构。

`ErrCode`见[附录 A：错误码表](#附录-a错误码表)

---

## 8. 数据模型

### 8.1 用户表 `user`

> **软删除与唯一约束**：`uid` 和 `email` 的 `UNIQUE` 约束需配合部分索引（`WHERE is_deleted = false`），否则软删除后同邮箱/uid 无法重新注册。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | `serial` | PK | 自增主键 |
| `uid` | `varchar(32)` | UNIQUE, NOT NULL | 用户唯一标识，系统生成（格式 `u{8位随机字母数字}`），对外展示用 |
| `student_id` | `varchar(32)` | UNIQUE, NULL | 学号（教育邮箱用户必填，OAuth 用户 NULL），不对外暴露 |
| `email` | `varchar(128)` | UNIQUE, NOT NULL | 主邮箱（注册邮箱，`@njupt.edu.cn`） |
| `password` | `varchar(256)` | NOT NULL | PBKDF2-HMAC-SHA512 哈希（含 salt、迭代次数参数） |
| `lark_id` | `varchar(64)` | NULL | 飞书 UnionID |
| `github_id` | `varchar(64)` | NULL | GitHub ID |
| `created_at` | `timestamptz` | NOT NULL | 创建时间 |
| `updated_at` | `timestamptz` | NOT NULL | 更新时间 |
| `token_version` | `int` | NOT NULL, DEFAULT 0 | Token 版本号，改密/重置密码时递增使所有 Token 失效 |
| `is_deleted` | `boolean` | NOT NULL, DEFAULT false | 软删除标记 |

### 8.2 资料表 `profile`

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | `serial` | PK | 自增主键 |
| `user_id` | `int` | FK → user.id, NOT NULL | 关联用户 |
| `nickname` | `varchar(64)` | NOT NULL | 昵称 |
| `email` | `varchar(128)` | NOT NULL | 邮箱（冗余） |
| `avatar` | `varchar(256)` | NOT NULL, DEFAULT '' | 头像 URL |
| `org_id` | `smallint` | DEFAULT -1 | 组织 ID |
| `bio` | `text` | NULL | 个人简介 |
| `link` | `varchar(256)[]` | NULL | 社交链接数组 |
| `badge` | `jsonb` | NULL | 徽章 JSON 数组 |
| `hide` | `varchar(30)[]` | NULL | 隐藏字段数组 |
| `updated_at` | `timestamptz` | NOT NULL | 资料最后更新时间 |
| `is_deleted` | `boolean` | NOT NULL, DEFAULT false | 软删除标记 |

### 8.3 组织表 `organize`

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | `smallint` | PK | 组织 ID（1-26） |
| `dep` | `varchar(64)` | NOT NULL | 部门名称 |
| `org` | `varchar(64)` | NULL | 组织名称 |

### 8.4 用户绑定邮箱表 `user_emails`

> **上限**：每个用户最多绑定 2 个第三方邮箱。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | `serial` | PK | 自增主键 |
| `user_id` | `int` | FK → user.id, NOT NULL | 关联用户 |
| `email` | `varchar(128)` | UNIQUE, NOT NULL | 绑定的第三方邮箱 |
| `is_verified` | `boolean` | NOT NULL, DEFAULT false | 是否已通过邮件验证 |
| `created_at` | `timestamptz` | NOT NULL | 创建时间 |
| `updated_at` | `timestamptz` | NOT NULL | 更新时间 |
| `is_deleted` | `boolean` | NOT NULL, DEFAULT false | 软删除标记 |

**约束**：
- `email` 全局唯一，配合部分索引 `WHERE is_deleted = false`
- 禁止绑定 `@njupt.edu.cn` 邮箱（教育邮箱走注册流程）
- 解绑后该邮箱进入 1 分钟冷却期（Redis 记录 `unbind_cooldown:{email}`），冷却期内不可重新绑定

### 8.5 OAuth 2.1 新增表

| 表名 | 用途 | 关键字段 |
|------|------|---------|
| `oauth_clients` | 客户端注册 | client_id, client_secret, client_type(confidential/public), redirect_uris, allowed_scopes, token_endpoint_auth_method |
| `oauth_consents` | 用户授权同意记录 | user_id, client_id, scopes, is_active（可撤销） |
| `oauth_authorization_codes` | 授权码存储 | code_hash, client_id, user_id, redirect_uri, code_challenge(PKCE), code_challenge_method, expires_at, is_used(单次使用) |
| `oauth_access_tokens` | Access Token 元数据 | token_hash, client_id, user_id, scope, grant_type, auth_code_id, expires_at, is_revoked |
| `oauth_refresh_tokens` | Refresh Token（支持 rotation） | token_hash, client_id, user_id, access_token_id, parent_refresh_token_id(自关联链), used_at(replay 检测), is_revoked |

**Scope 列表**：系统支持以下 scope：

| Scope | 说明 |
|-------|------|
| `profile` | 读取用户昵称、头像、组织、简介 |
| `email` | 读取用户邮箱 |
| `openid` | 获取用户唯一标识（uid） |

**设计要点**：
- Token 原文存 Redis，表中只存 SHA-256 hash
- Refresh Token 通过 `parent_refresh_token_id` 自关联实现 rotation，replay 攻击时级联撤销整条链
- Scope 采用标准空格分隔字符串（如 `"profile email"`）
- 所有表保留 `is_deleted` 软删除
- 生产环境需迁移老 `oauth2_clients` / `oauth2_tokens` 数据

### 8.6 登录设备表 `login_devices`

> **双写策略**：设备信息同时写入本表（持久化）和 Redis Sorted Set（快速查询/淘汰）。Redis 故障时可从本表恢复。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | `serial` | PK | 自增主键 |
| `user_id` | `int` | FK → user.id, NOT NULL | 关联用户 |
| `device_fingerprint` | `varchar(64)` | NOT NULL | 设备指纹（由客户端生成或后端根据 UA+IP 哈希） |
| `ip_address` | `varchar(45)` | NOT NULL | 登录 IP（支持 IPv6） |
| `user_agent` | `varchar(512)` | NOT NULL | 浏览器/设备标识 |
| `token_family_id` | `varchar(64)` | NOT NULL | 关联的 Token Family 标识 |
| `created_at` | `timestamptz` | NOT NULL | 首次登录时间 |
| `last_used_at` | `timestamptz` | NOT NULL | 最后活跃时间 |
| `is_deleted` | `boolean` | NOT NULL, DEFAULT false | 软删除标记（淘汰最旧设备时标记） |

**Redis 结构**：`user_tokens:{user_id}` → Sorted Set，member 为 `token_family_id`，score 为 `last_used_at` 时间戳。新登录时检查 cardinality，≥5 时移除 score 最小的 member 并级联撤销对应 Token Family。

---

## 9. 关键流程与约定

端点列表见 [5.1](#51-功能与端点列表)。以下为认证方式和核心流程：

### 9.1 认证方式

- **Access Token**：`Authorization: Bearer <token>`，15 分钟有效期
- **Refresh Token**：`Refresh-Token` Header（或 OAuth 2.1 `/token` 端点），7 天有效期
- **Ticket**：`*-TICKET` Header，用于注册/登录/重置/绑定流程
- **第一方应用**：public client，PKCE-S256，无 client_secret
- **第三方应用**：通过 `/oauth2/register` 注册获得 client_id/client_secret
- **OAuth 2.1 端点**响应为标准 `error`/`error_description`，与业务端点格式区分
- **登录回调**（`/login/{provider}/callback`）与 **绑定回调**（`/profile/bind/{provider}/callback`）为独立 handler

### 9.2 注册流程

```
[POST /verify/account 输入 @njupt.edu.cn 邮箱]
    |
    ▼
[校验邮箱格式 + 是否已注册]
    |
    ├─ 格式错误或已注册 ──→ 返回错误
    └─ 校验通过 ──→ [生成 Register-Ticket]
                       |
                       ▼
            [POST /sendEmail 发送验证码]
                       |
                       ▼
            [用户收到验证码 S-XXXXX]
                       |
                       ▼
            [POST /verify/captcha 校验验证码]
                       |
                       ├─ 验证码错误 ──→ 返回错误
                       └─ 校验通过 ──→ [POST /user/register 设置密码]
                                          |
                                          ▼
                               [校验密码强度 6-64 位含字母+数字]
                                          |
                                          ├─ 强度不足 ──→ 返回错误
                                          └─ 通过 ──→ [创建 user + profile]
                                                      → [PBKDF2-HMAC-SHA512 哈希密码]
                                                      → [生成 Access + Refresh Token]
                                                      → 注册完成
```

### 9.3 登录流程

**分阶段登录**：先验证账号获取 Login-Ticket，再凭 Ticket 完成登录。

```
[POST /verify/account 输入学号/邮箱]
    |
    ▼
[查询 user.email 或 user_emails.email]
    |
    ├─ 账号不存在 ──→ 返回 10006
    |
    └─ 账号存在 ──→ [生成 Login-Ticket]
                       |
                       ▼
            返回 Login-Ticket（有效期 5 分钟）
                       |
                       ▼
[POST /user/login 输入密码 + Login-Ticket Header]
    |
    ▼
[校验 Login-Ticket 有效]
    |
    ├─ Ticket 无效 ──→ 返回 20007
    |
    └─ Ticket 有效 ──→ [校验 PBKDF2-HMAC-SHA512 密码]
                           |
                           ├─ 密码错误 ──→ 返回 10005
                           └─ 密码正确 ──→ [检查 token_version 匹配]
                                              |
                                              ▼
                                   [检查当前设备数]
                                              |
                                              ├─ 已达 5 设备 ──→ [淘汰最旧设备]
                                              └─ 未满 5 设备
                                                     |
                                                     ▼
                                          [生成 Access + Refresh Token]
                                                     |
                                                     ▼
                                          [Redis 记录 Token Family]
                                          [DB 记录/更新 login_devices]
                                                     |
                                                     ▼
                                          返回双 Token
```

### 9.4 重置密码流程

```
[POST /verify/account 输入邮箱]
    |
    ▼
[校验账号是否存在]
    |
    ├─ 账号不存在 ──→ 返回 10006
    └─ 账号存在 ──→ [生成 ResetPwd-Ticket]
                       |
                       ▼
            [POST /sendEmail 发送验证码]
                       |
                       ▼
            [用户收到验证码]
                       |
                       ▼
            [POST /verify/captcha 校验验证码]
                       |
                       ├─ 验证码错误 ──→ 返回 30002
                       └─ 校验通过 ──→ [POST /user/resetPassword 设置新密码]
                                          |
                                          ▼
                               [校验密码强度]
                                          |
                                          ├─ 强度不足 ──→ 返回 10003
                                          └─ 通过 ──→ [PBKDF2-HMAC-SHA512 哈希新密码]
                                                      → [递增 token_version]
                                                      → [使所有现有 Token 失效]
                                                      → 重置成功
```

### 9.5 OAuth 注册补全流程

首次 OAuth 登录（GitHub/飞书）且未绑定任何账号时：

```
[OAuth 回调]
    |
    ▼
[检查 provider_user_id 是否已绑定]
    |
    ├─ 已绑定 ──→ [生成 Access + Refresh Token] ──→ 登录成功
    |
    └─ 未绑定
           |
           ▼
    [返回 OAuth-Ticket + 临时用户信息（昵称/头像）]
           |
           ▼
    [前端引导用户输入邮箱 → 发送验证码]
           |
           ▼
    [POST /user/oauthRegister]
    Body: oauthTicket, email, captcha, password
           |
           ▼
    [后端校验]
           |
           ├─ email 已被注册 ──→ 返回错误（可选：换邮箱 或 走「绑定已有账号」流程）
           │                          │
           │                          ▼
           │               [调用 POST /user/oauthBindExisting]
           │               Body: oauthTicket, email, password
           │                          │
           │                          ▼
           │               [校验 email + 密码匹配已有账号]
           │               （无需登录态，凭密码验证账号所有权）
           │                          │
           │                          ├─ 校验失败 ──→ 返回错误
           │                          └─ 校验通过 ──→ [绑定 OAuth 到已有账号]
           │                                                      → 绑定成功
           |
           └─ email 可用 ──→ [创建 user + profile 记录]
                           → [绑定 OAuth]
                           → [生成 Token]
                           → 注册完成
```

**uid 生成规则**：所有用户注册时系统统一生成唯一 `uid`，格式 `u{8位随机字母数字}`（如 `u7a3k9p2`），不对外暴露学号。OAuth 注册用户 `student_id` 为 NULL。

### 9.6 邮箱绑定流程

已登录用户绑定第三方邮箱：

```
[POST /profile/bindEmail]
    |
    ▼
[校验]
    |
    ├─ 邮箱格式无效 ──→ 返回错误
    ├─ 邮箱是 @njupt.edu.cn ──→ 返回错误（教育邮箱不可绑定）
    ├─ 该用户已绑 2 个邮箱 ──→ 返回错误（已达上限）
    ├─ 该邮箱已被绑定 ──→ 返回错误
    └─ 校验通过
           |
           ▼
    [发送验证码邮件，生成 BindEmail-Ticket]
           |
           ▼
[用户收到验证码]
    |
    ▼
[POST /profile/verifyBindEmail]
    Body: email, captcha, bindEmailTicket
           |
           ▼
    [校验 Ticket + 验证码]
           |
           ├─ 验证失败 ──→ 返回错误
           └─ 验证通过 ──→ [创建 user_emails 记录]
                           → [使 Ticket 失效]
                           → 绑定成功
```

**解绑流程**：
- 调用 `POST /profile/unbindEmail`，body 传入要解绑的邮箱
- 后端发送验证码到该邮箱，生成 UnbindEmail-Ticket
- 用户输入验证码
- 调用 `POST /profile/confirmUnbindEmail`，body: email, captcha, unbindEmailTicket
- 校验 Ticket + 验证码通过后，删除 `user_emails` 对应记录（软删除）
- Redis 设置 `unbind_cooldown:{email}`，TTL 60 秒
- 冷却期内该邮箱不可被任何用户重新绑定

**登录适配**：
- `POST /user/login` 输入邮箱时，同时查 `user.email`（教育邮箱）和 `user_emails.email`（绑定邮箱）
- 密码验证逻辑不变

### 9.7 OAuth 2.1 端点参数

**授权端点 `GET /oauth2/authorize`**：

> **用户认证**：调用此端点前，用户需先通过第一方登录获取 Session Cookie。授权端点通过 Session 识别用户身份，未登录时 302 重定向到登录页。

| 参数 | 必填 | 说明 |
|------|------|------|
| `response_type` | 是 | 固定为 `code` |
| `client_id` | 是 | 客户端 ID |
| `redirect_uri` | 是 | 必须在客户端注册的白名单内 |
| `scope` | 否 | 空格分隔的权限列表，如 `profile email` |
| `state` | 推荐 | CSRF 防护，原样回传 |
| `code_challenge` | 是 | PKCE: Base64URL(SHA256(code_verifier)) |
| `code_challenge_method` | 是 | 固定为 `S256` |

**响应**：
- 成功：302 重定向到 `redirect_uri?code={授权码}&state={state}`，授权码 10 分钟有效，单次使用
- 用户未登录：302 重定向到登录页，登录完成后继续授权流程
- 用户拒绝授权：302 重定向到 `redirect_uri?error=access_denied`
- 参数错误：302 重定向到 `redirect_uri?error=invalid_request`

**Token 端点 `POST /oauth2/token`**：

| 参数 | 必填 | 说明 |
|------|------|------|
| `grant_type` | 是 | `authorization_code` 或 `refresh_token` |
| `code` | 条件 | 授权码（`grant_type=authorization_code` 时必填） |
| `refresh_token` | 条件 | Refresh Token（`grant_type=refresh_token` 时必填） |
| `redirect_uri` | 条件 | 必须与授权请求一致（`authorization_code` 时必填） |
| `client_id` | 是 | 客户端 ID |
| `client_secret` | 条件 | confidential client 必填，public client（含第一方）无需 |
| `code_verifier` | 条件 | PKCE 原始 code_verifier（`authorization_code` 时必填） |

**响应**：
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2g...",
  "scope": "profile email"
}
```

**撤销端点 `POST /oauth2/revoke`**：

| 参数 | 必填 | 说明 |
|------|------|------|
| `token` | 是 | 要撤销的 Access Token 或 Refresh Token |
| `token_type_hint` | 否 | `access_token` 或 `refresh_token` |

**自省端点 `POST /oauth2/introspect`**：

| 参数 | 必填 | 说明 |
|------|------|------|
| `token` | 是 | 要检查的 Token |

**响应**：
```json
{
  "active": true,
  "scope": "profile email",
  "client_id": "abc123",
  "username": "user@example.com",
  "exp": 1798761600
}
```

---

## 10. 依赖与风险

### 10.1 外部依赖

| 依赖 | 用途 | 风险 |
|------|------|------|
| 腾讯云 COS | 头像存储 | 审核 API 变动 |
| 飞书 SMTP | 验证邮件发送 | 发信频率限制 |
| 飞书开放平台 | OAuth 登录 | API 变动 |
| GitHub | OAuth 登录 | API 限流/变动 |
| 学校邮箱系统 | 邮箱可达性 | 邮件进垃圾箱 |
| OAuth 2.1 标准 | 认证授权体系 | 规范变动（draft → RFC） |

### 10.2 风险

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| 老用户密码迁移 | 高 | PBKDF2-HMAC-SHA512 新格式；老用户 SHA512 密码登录验证通过后自动重哈希 |
| 前端 API 契约变更 | 中 | 仅在性能或安全需求迫使时修改，其余保持；上线后对接修复 |
| 数据库迁移 | 中 | 新库 + 迁移脚本；老 oauth2 数据需迁移到新 schema |
| OAuth 2.1 规范变动 | 中 | 当前基于 draft，RFC 正式发布后需评估差异 |
| 硬切换停机 | 中 | 选择低峰期，提前通知用户 |
| 5 设备上限用户体验 | 低 | 产品已确认接受 |

### 10.3 发布策略

- **切换方式**：硬切换（停机部署）
- **数据库**：新库 + 迁移脚本；生产环境直连已有 PostgreSQL，开发用 Docker
- **上线后**：与前端对接修复优化功能

---

## 11. 实现顺序（Todo）

按以下顺序实现，打勾表示已完成：

- [x] 项目初始化、数据库设计、CI/CD
- [ ] 用户认证（注册 / 登录 / 验证码 / 改密 / 重置密码）
- [ ] 用户资料管理（查看 / 编辑 / 头像上传）
- [ ] OAuth 登录（GitHub / 飞书）
- [ ] OAuth 绑定 / 解绑 + 注册补全
- [ ] 限流与防刷
- [ ] 操作日志 + 健康检查
- [ ] 头像内容审核（腾讯云 COS）
- [ ] OAuth2 授权服务端（OAuth 2.1）
- [ ] OAuth2 客户端注册 API
- [ ] 管理后台
- [ ] 审计日志
- [ ] 测试、联调、上线

---

## 12. 附录

### 附录 A：错误码表

| 错误码 | 含义 |
|--------|------|
| `200` | 成功 |
| `10001` | 请求参数错误
| `10002` | 用户名格式错误
| `10003` | 密码格式错误
| `10004` | 密码为空
| `10005` | 登录失败 | 账号或密码错误 |
| `10006` | 账号不存在 | 登录时账号未注册 |
| `10007` | 账号已存在 | 注册时邮箱已被占用 |
| `10008` | 操作太频繁 | 限流触发 |
| `10009` | 权限不足 | 需要登录态或更高权限 |
| `10010` | OAuth 未绑定 | |
| `10011` | 用户不存在 | |
| `10012` | OAuth 已绑定其他账号 | 该第三方账号已绑定到另一个用户 |
| `10013` | OAuth 绑定失败 | 绑定过程中 provider 返回错误 |
| `10014` | 解绑失败 | 解绑后无可用登录方式，或该 OAuth 未绑定 |
| `10015` | 邮箱已被注册 | OAuth 注册补全时邮箱已被占用 |
| `10016` | 绑定邮箱数量已达上限 | 该用户已绑定 2 个第三方邮箱 |
| `10017` | 邮箱已被其他用户绑定 | 该邮箱已被其他账号绑定 |
| `10018` | 解绑冷却中 | 该邮箱解绑后 1 分钟内不可重新绑定 |
| `20001` | Token 已过期 | 通用 Token 过期 |
| `20002` | Access Token 过期 | |
| `20003` | Token 生成失败 | |
| `20004` | Token 无效 | |
| `20005` | Refresh Token 无效或过期 | |
| `20006` | Token 解析失败 | |
| `20007` | Ticket 不正确 | |
| `20008` | Ticket 不存在或过期 | |
| `20009` | Token 版本不匹配 | `token_version` 校验失败 |
| `30001` | 邮件发送失败 | |
| `30002` | 验证码错误 | |
| `30003` | 邮箱格式错误 | |
| `30004` | 绑定邮箱验证码错误 | 邮箱绑定流程验证码不正确 |
| `30005` | 绑定邮箱 Ticket 无效 | BindEmail-Ticket 不存在或已过期 |
| `30006` | 解绑验证码错误 | 邮箱解绑流程验证码不正确 |
| `40001` | 账号验证失败 | |
| `40002` | 密码验证失败 | |
| `40003` | 旧密码错误 | 修改密码时旧密码校验失败 |
| `50000` | 内部错误 | |
| `60001` | `invalid_request` | OAuth 2.1 请求参数错误 |
| `60002` | `invalid_client` | OAuth 2.1 客户端认证失败 |
| `60003` | `invalid_grant` | OAuth 2.1 授权码或 Refresh Token 无效/过期 |
| `60004` | `unauthorized_client` | OAuth 2.1 客户端无权使用此授权类型 |
| `60005` | `unsupported_grant_type` | OAuth 2.1 不支持的授权类型 |
| `60006` | `invalid_scope` | OAuth 2.1 请求的 scope 无效/未授权 |
| `60007` | `server_error` | OAuth 2.1 授权服务端内部错误 |
| `60008` | `temporarily_unavailable` | OAuth 2.1 服务端暂时不可用 |
| `70001` | 注册信息不完整 | 缺少必填字段 |
| `70002` | 注册阶段错误 | 通用注册流程错误 |
| `70004` | 重置密码失败 | |
| `70005` | OAuth 注册补全失败 | 参数缺失或 Ticket 无效 |
| `80000` | 用户资料不存在 | |
| `80001` | 组织 ID 无效 | |
| `80002` | 隐藏字段无效 | |
| `80003` | 邮箱绑定失败 | 参数缺失或验证不通过 |
| `90000` | 通知发送失败 | |
| `90001` | 图片处理失败 | |
| `90002` | 图片 URL 无效 | |

### 附录 B：前端兼容性清单

| # | 前端问题 | 位置 | 修复方案 |
|---|----------|------|----------|
| 1 | Badge 时间字段名错误 | `lib/api/types.ts:23` | `create_at` → `created_at` |
| 2 | 验证码正则不匹配 | `lib/validations/auth.ts:5` | `/^\d{5}$/` → `/^S-[A-Z0-9]{5}$/` |
| 3 | 验证码输入框长度 | 注册/登录 Step-2 | `maxLength={5}` → `maxLength={7}` |
| 4 | 密码最小长度过严 | `lib/validations/auth.ts:6` | `.{8,}` → `.{6,}` |
| 5 | Token Header 名 | `lib/api/client.ts` | `TOKEN` → `Authorization: Bearer` |

### 附录 C：术语表

| 术语 | 说明 |
|------|------|
| Ticket | 分阶段验证令牌，用于注册/登录/重置密码/OAuth 绑定流程 |
| Register-Ticket | 注册流程阶段凭证，有效期 5 分钟 |
| Login-Ticket | 登录流程阶段凭证，有效期 5 分钟 |
| ResetPwd-Ticket | 密码重置流程阶段凭证，有效期 6 分钟 |
| OAuth-Ticket | OAuth 绑定/注册补全流程凭证，有效期 3 分钟 |
| Access Token | 短期访问令牌，15 分钟有效期，放 `Authorization: Bearer` Header |
| Refresh Token | 长期刷新令牌，7 天有效期，放 `Refresh-Token` Header |
| OAuth | 开放授权协议，支持第三方账号登录 |
| COS | 腾讯云对象存储，用于头像存储 |
| OAuth 2.1 | OAuth 2.0 的更新版，PKCE 强制、移除隐式授权和密码凭证授权 |
| PKCE | Proof Key for Code Exchange，授权码流程的安全扩展，防止授权码拦截攻击 |
| Client | OAuth 客户端，分为 confidential（能安全保存 secret）和 public（如 SPA） |
| Scope | 权限范围，空格分隔的字符串（如 `"profile email"`） |
| Authorization Grant | 授权许可，用户同意客户端访问其资源的凭证 |
| Token Rotation | Refresh Token 轮换，每次刷新时发放新 Token，旧 Token 失效 |
| Token Family | 由同一授权链产生的相关 Token 集合，replay 攻击时级联撤销 |
| BindEmail-Ticket | 邮箱绑定流程凭证，有效期 5 分钟 |
| UnbindEmail-Ticket | 邮箱解绑流程凭证，有效期 5 分钟 |
| 第三方邮箱 | 非 `@njupt.edu.cn` 的邮箱，绑定后可用于登录 |
| SAST | 南京邮电大学校大学生科学技术协会 |

---

## 13. 已决策项

以下问题已在本 PRD 评审过程中确认：

| 问题 | 决策 | 说明 |
|------|------|------|
| 密码哈希 | PBKDF2-HMAC-SHA512 | 新用户默认；老用户 SHA512 密码登录验证后自动重哈希 |
| 设备上限 | 最多 5 设备 | Redis Sorted Set 管理，超出淘汰最旧设备 |
| OAuth2 客户端注册 | 开放注册 | 任何人可调用 `/oauth2/register` 创建客户端 |
| QQ 登录 | 不做 | 已舍去 |
| API 契约修改 | 仅在性能或安全需求迫使时修改 | 端点路径无 `/api/v1/` 前缀；V1 `TOKEN` Header 改为标准 `Authorization: Bearer` |
| 第一方登录 | 走标准 OAuth2 | 作为 public client，PKCE-S256，无 client_secret |
| Access Token 签名 | RS256 | 非对称签名，支持资源服务器独立验签 |
| 即时失效机制 | `token_version` | user 表加字段，改密时自增使所有 Token 失效 |

---

*文档版本 v1.2 | 最后更新 2026-05-25*
