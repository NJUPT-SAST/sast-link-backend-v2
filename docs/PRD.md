# SAST Link Backend V2 — 产品需求文档 (PRD)

| 项目 | 内容 |
|------|------|
| 产品名称 | SAST Link Backend V2 |
| 版本 | v1.0 |
| 日期 | 2026-05-23 |
| 状态 | 待确认 |

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

V1 为完全体设计，以下功能全部在 V1 范围内实现，仅存在开发顺序差异：

- 账号注册/登录/登出/改密/重置密码
- 邮箱验证码
- 用户资料管理（查看/编辑/头像上传）
- GitHub / 飞书 OAuth 登录 + 主动绑定/解绑
- OAuth 首次登录注册补全
- 限流与防刷
- 操作日志 + 健康检查
- 头像内容审核（腾讯云 COS）
- OAuth2 授权服务端（外部系统对接，采用 OAuth 2.1 标准）
- 管理后台
- 审计日志

---

### 1.4 非目标（Non-goals）

以下功能/策略**不在 V2 范围内**：

- **API 契约**：不保证 100% 前端零改动，仅在"引入极大优化"时修改响应格式
- **认证协议**：不限制为 JWT HS256，全面引入 OAuth 2.1 标准
- **管理后台**：第一版不实现细粒度 RBAC，仅基础成员管理
- **历史数据**：不迁移老用户历史操作日志，V2 从零开始记录
- **OAuth2 模式**：不限于授权码模式，按 OAuth 2.1 标准实现
- **QQ 登录**：V2 不做，已舍去

---

## 2. 目标用户

| 用户类型 | 描述 | 核心诉求 |
|----------|------|----------|
| **SAST 成员** | 南邮 SAST 的学生成员 | 快速注册、管理个人资料、使用统一身份登录各 SAST 项目 |
| **外部开发者** | 其他 SAST 项目的前后端开发者 | 通过 OAuth2 接入 SAST 账号体系（V2） |
| **前端团队** | SAST Link 前端维护者 | 稳定、文档清晰的 API |
| **运维人员** | 系统维护者 | 可监控、易部署、有问题能定位 |

---

## 3. 用户故事

### US-1：注册账号
> 作为 SAST 新成员，我希望通过学号邮箱注册账号，以便使用 SAST 的各项服务。

**验收标准：**
- 支持 `@njupt.edu.cn` 邮箱注册
- 注册流程分阶段验证：账号验证 → 发送邮件 → 输入验证码 → 设置密码
- 密码 6-64 位，必须同时含字母和数字
- 注册成功后自动创建默认资料

### US-2：登录
> 作为 SAST 成员，我希望通过学号/邮箱和密码登录，以便访问我的账号。

**验收标准：**
- 支持学号或邮箱登录
- 登录成功后返回双 Token（Access + Refresh）
- Access Token 15 分钟有效期，Refresh Token 7 天
- 支持单设备登录（新登录踢掉旧登录）

### US-3：第三方登录
> 作为 SAST 成员，我希望通过 GitHub 或飞书快速登录，以便不用记密码。

**验收标准：**
- 支持 GitHub OAuth 登录
- 支持飞书 OAuth 登录
- 首次 OAuth 登录若无已有账号，进入「补全注册」流程：绑定邮箱 → 输入验证码 → 设置密码 → 完成注册，系统自动生成 `uid`
- 已绑定账号直接登录
- 登录后可主动绑定/解绑第三方账号
- 解绑仅针对第三方登录方式，邮箱不可解绑，且至少保留一种登录方式

### US-4：管理个人资料
> 作为 SAST 成员，我希望编辑我的昵称、头像、组织、简介和社交链接，以便展示个人信息。

**验收标准：**
- 支持修改昵称、头像、组织、简介、社交链接
- 支持设置隐私字段（隐藏 bio/link/badge）
- 组织选择后显示部门和组织名称

### US-5：查看他人资料
> 作为 SAST 成员，我希望查看其他成员的资料，以便了解团队成员。

**验收标准：**
- 公开资料显示昵称、组织、简介、徽章
- 尊重用户隐私设置（隐藏字段不显示）
- 徽章显示获得时间和描述

---

## 4. 产品目标与成功指标

| 目标 | 指标 | 目标值 |
|------|------|--------|
| API 稳定性 | 单元测试覆盖率 | ≥ 80%（显式展示于 README，不卡门禁） |
| 注册成功率 | 注册完成率 | ≥ 95% |
| 登录性能 | P99 登录响应时间 | ≤ 200ms |
| 系统可用性 | 服务可用时间 | ≥ 99.9% |
| 代码质量 | golangci-lint 全绿 | 0 警告 |
| CI 质量 | 安全扫描（gosec + govulncheck） | 0 高危漏洞 |
| CI 质量 | 构建验证 + race detector | 全绿 |
| CI 质量 | 依赖检查（go mod tidy） | 无未提交变更 |

---

## 5. 功能需求

### 5.1 V1 功能列表

| ID | 需求 | 用户故事 | 验收标准 |
|----|------|----------|----------|
| F-1 | 账号验证 | US-1, US-2 | GET `/verify/account` 验证账号是否存在/可用，返回对应 Ticket |
| F-2 | 验证码校验 | US-1 | POST `/verify/captcha` 校验邮箱验证码，验证码格式 `S-XXXXX`（5位） |
| F-3 | 发送验证邮件 | US-1 | POST `/sendEmail` 发送含验证码的邮件，限流 2 次/分钟 |
| F-4 | 用户注册 | US-1 | POST `/user/register` 完成注册，密码 6-64 位，含字母+数字 |
| F-5 | 用户登录 | US-2 | POST `/user/login` 返回 Access Token + Refresh Token |
| F-6 | 用户登出 | US-2 | POST `/user/logout` 使当前 Token 失效 |
| F-7 | 修改密码 | US-2 | POST `/user/changePassword` 验证旧密码后修改 |
| F-8 | 重置密码 | US-1 | POST `/user/resetPassword` 通过 Ticket 重置密码 |
| F-9 | 获取用户信息 | US-2 | GET `/user/info` 返回 email + userId（string 类型） |
| F-10 | 获取用户资料 | US-4, US-5 | GET `/profile/getProfile` 返回完整资料，含 dep/org 字符串 |
| F-11 | 修改用户资料 | US-4 | POST `/profile/changeProfile` 修改昵称/组织/简介/链接/隐私 |
| F-12 | 上传头像 | US-4 | POST `/profile/uploadAvatar` 返回字符串路径 |
| F-13 | GitHub 登录 | US-3 | GET `/login/github` + `/login/github/callback` |
| F-14 | 飞书登录 | US-3 | GET `/login/lark` + `/login/lark/callback` |
| F-15 | OAuth 绑定状态 | US-3 | GET `/profile/bindStatus` 返回已绑定的 OAuth 列表 |
| F-16 | GitHub 绑定 | US-3 | `GET /profile/bind/github` 发起绑定（需登录态），302 重定向到 GitHub 授权页 |
| F-17 | GitHub 绑定回调 | US-3 | `GET /profile/bind/github/callback` 绑定回调，成功后返回绑定结果 |
| F-18 | 飞书绑定 | US-3 | `GET /profile/bind/lark` 发起绑定（需登录态），302 重定向到飞书授权页 |
| F-19 | 飞书绑定回调 | US-3 | `GET /profile/bind/lark/callback` 绑定回调，成功后返回绑定结果 |
| F-20 | 解除第三方绑定 | US-3 | POST `/profile/unbind` 解除指定 provider 绑定，邮箱不可解绑 |
| F-21 | OAuth 注册补全 | US-3 | POST `/user/oauthRegister` OAuth 首次登录后补全注册（绑定邮箱+验证码+设密码） |
| F-22 | 限流与防刷 | — | 对登录、注册、发邮件等接口增加限流 |
| F-23 | 操作日志 | — | 记录关键操作（登录、密码修改、资料变更） |
| F-24 | 健康检查 | — | `/ping` 或 `/health` 端点 |
| F-25 | 头像内容审核 | US-4 | 上传头像后触发腾讯云 COS 内容审核 |
| F-26 | OAuth2 授权服务端 | — | 采用 OAuth 2.1 标准，为外部 SAST 项目提供授权服务 |
| F-27 | OAuth2 客户端注册 | — | POST `/oauth2/register` 动态注册 OAuth 客户端 |
| F-28 | 管理后台 | — | 成员管理、组织管理、徽章管理、成就系统 |
| F-29 | 审计日志 | — | 完整的操作审计 |

---

## 6. 非功能需求

### 6.1 性能

- API P99 响应时间 ≤ 200ms（不含外部服务调用）
- 数据库查询需有索引，慢查询日志阈值 100ms
- Redis 操作 P99 ≤ 10ms

### 6.2 安全

- 密码存储：SHA512（与老后端兼容，登录时做好加密和安全验证）
- Token：OAuth 2.1 + RS256，Access Token 15 分钟，Refresh Token 7 天
- 设备上限：Redis 中每个用户最多保留 5 个有效 Token Family，新登录淘汰最旧设备
- Token 失效策略：修改密码 / 重置密码时递增 `token_version`，使所有现有 Token 失效；登出仅清除当前设备 Token
- Refresh Token 轮转：每次刷新发放新 Refresh Token，旧 Token 立即失效；检测到旧 Token 重放时撤销整个 Token Family
- PKCE：所有客户端（含第一方）强制使用 PKCE-S256
- 验证码：5 分钟有效期，Redis 存储
- HTTPS 强制
- SQL 注入防护：使用参数化查询（ORM）
- XSS 防护：API 返回纯 JSON，不做 HTML 渲染

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

### 6.3 可靠性

-  graceful shutdown：处理完当前请求再退出
- 数据库连接池：最大 20 连接，连接超时 5 秒
- Redis 断连自动重连

### 6.4 可观测性

- 结构化日志（JSON 格式）
- 关键接口请求量/延迟/错误率指标
- 慢查询告警

### 6.5 兼容性

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
| 密码哈希 | SHA512 | —（兼容老用户） |
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

---

## 8. 数据模型

### 8.1 用户表 `user`

> **软删除与唯一约束**：`uid` 和 `email` 的 `UNIQUE` 约束需配合部分索引（`WHERE is_deleted = false`），否则软删除后同邮箱/uid 无法重新注册。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | `serial` | PK | 自增主键 |
| `uid` | `varchar(32)` | UNIQUE, NOT NULL | 用户 ID（学号/邮箱前缀） |
| `email` | `varchar(128)` | UNIQUE, NOT NULL | 邮箱 |
| `password` | `varchar(128)` | NOT NULL | SHA512 哈希 |
| `qq_id` | `varchar(64)` | NULL | QQ OpenID |
| `lark_id` | `varchar(64)` | NULL | 飞书 UnionID |
| `github_id` | `varchar(64)` | NULL | GitHub ID |
| `wechat_id` | `varchar(64)` | NULL | 微信 OpenID |
| `created_at` | `timestamptz` | NOT NULL | 创建时间 |
| `updated_at` | `timestamptz` | NOT NULL | 更新时间 |
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
| `is_deleted` | `boolean` | NOT NULL, DEFAULT false | 软删除标记 |

### 8.3 组织表 `organize`

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | `smallint` | PK | 组织 ID（1-26） |
| `dep` | `varchar(64)` | NOT NULL | 部门名称 |
| `org` | `varchar(64)` | NULL | 组织名称 |

### 8.4 OAuth 2.1 新增表

| 表名 | 用途 | 关键字段 |
|------|------|---------|
| `oauth_clients` | 客户端注册 | client_id, client_secret, client_type(confidential/public), redirect_uris, allowed_scopes, token_endpoint_auth_method |
| `oauth_consents` | 用户授权同意记录 | user_id, client_id, scopes, is_active（可撤销） |
| `oauth_authorization_codes` | 授权码存储 | code_hash, client_id, user_id, redirect_uri, code_challenge(PKCE), code_challenge_method, expires_at, is_used(单次使用) |
| `oauth_access_tokens` | Access Token 元数据 | token_hash, client_id, user_id, scope, grant_type, auth_code_id, expires_at, is_revoked |
| `oauth_refresh_tokens` | Refresh Token（支持 rotation） | token_hash, client_id, user_id, access_token_id, parent_refresh_token_id(自关联链), used_at(replay 检测), is_revoked |

**设计要点**：
- Token 原文存 Redis，表中只存 SHA-256 hash
- Refresh Token 通过 `parent_refresh_token_id` 自关联实现 rotation，replay 攻击时级联撤销整条链
- Scope 采用标准空格分隔字符串（如 `"profile email"`）
- 所有表保留 `is_deleted` 软删除
- 生产环境需迁移老 `oauth2_clients` / `oauth2_tokens` 数据

---

## 9. API 规范（摘要）

详见各端点详细定义，以下为关键约定：

### 9.1 认证方式

- **OAuth 2.1 Access Token**：放在 `Authorization: Bearer <token>` Header
- **Refresh Token**：放在 `Refresh-Token` Header（或通过 OAuth 2.1 `/token` 端点刷新）
- **Ticket**（注册/登录/重置）：放在对应 `*-TICKET` Header
- **第一方应用**：作为 public client，使用 PKCE-S256，无 client_secret
- **第三方应用**：通过 `/oauth2/register` 注册后获得 client_id/client_secret

### 9.2 关键端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/verify/account` | 账号验证，返回 Ticket |
| POST | `/api/v1/verify/captcha` | 验证码校验 |
| POST | `/api/v1/sendEmail` | 发送验证邮件 |
| POST | `/api/v1/user/register` | 注册 |
| POST | `/api/v1/user/login` | 登录，返回双 Token |
| POST | `/api/v1/user/logout` | 登出 |
| POST | `/api/v1/user/changePassword` | 修改密码 |
| POST | `/api/v1/user/resetPassword` | 重置密码 |
| POST | `/api/v1/user/refresh` | 用 Refresh Token 换取新的 Access Token |
| GET | `/api/v1/user/info` | 用户信息（email + userId） |
| POST | `/api/v1/user/oauthRegister` | OAuth 首次登录后补全注册 |
| GET | `/api/v1/profile/getProfile` | 完整资料 |
| POST | `/api/v1/profile/changeProfile` | 修改资料 |
| POST | `/api/v1/profile/uploadAvatar` | 上传头像，返回字符串路径 |
| GET | `/api/v1/profile/bindStatus` | OAuth 绑定状态 |
| GET | `/api/v1/profile/bind/github` | 发起 GitHub 绑定（需登录态），302 重定向 |
| GET | `/api/v1/profile/bind/github/callback` | GitHub 绑定回调 |
| GET | `/api/v1/profile/bind/lark` | 发起飞书绑定（需登录态），302 重定向 |
| GET | `/api/v1/profile/bind/lark/callback` | 飞书绑定回调 |
| POST | `/api/v1/profile/unbind` | 解除第三方绑定 |
| GET | `/api/v1/login/github` | GitHub 登录入口 |
| GET | `/api/v1/login/github/callback` | GitHub 回调 |
| GET | `/api/v1/login/lark` | 飞书登录入口 |
| GET | `/api/v1/login/lark/callback` | 飞书回调 |
| POST | `/api/v1/oauth2/register` | 动态注册 OAuth 客户端 |
| GET | `/api/v1/oauth2/authorize` | OAuth 2.1 授权端点（PKCE 强制） |
| POST | `/api/v1/oauth2/token` | OAuth 2.1 Token 端点 |
| POST | `/api/v1/oauth2/revoke` | Token 撤销端点 |
| POST | `/api/v1/oauth2/introspect` | Token 自省端点 |
| GET | `/api/v1/.well-known/oauth-authorization-server` | OAuth 2.1 发现端点 |

> **注意**：OAuth **登录回调**（`/login/{provider}/callback`）与 **绑定回调**（`/profile/bind/{provider}/callback`）为独立的 handler，不共用逻辑。登录回调处理未登录态的认证流程；绑定回调处理已登录态的账号关联。

> **OAuth 2.1 端点响应格式**：使用标准格式（`error`/`error_description`），与业务端点的 `Success/ErrCode/ErrMsg/Data` 格式区分。

### 9.3 OAuth 注册补全流程

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
           ├─ email 已被注册 ──→ 返回错误（要求换邮箱或走绑定已有账号流程）
           |
           └─ email 可用 ──→ [创建 user + profile 记录]
                           → [绑定 OAuth]
                           → [生成 Token]
                           → 注册完成
```

**uid 生成规则**：纯 OAuth 注册用户无学号，系统生成唯一 `uid`，格式 `u{8位随机字母数字}`（如 `u7a3k9p2`）。

### 9.4 错误码

保留老后端全部 31 个 5 位错误码。**新功能（绑定/解绑/OAuth 注册补全）允许在对应分类范围内新增错误码**，详见附录 A。

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
| 老用户密码迁移 | 高 | 保持 SHA512 兼容，登录时做好加密和安全验证 |
| 前端 API 契约变更 | 中 | 仅在"极大优化"时修改，其余保持；上线后对接修复 |
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
| `10001` | 请求参数错误 |
| `10002` | 用户名格式错误 |
| `10003` | 密码格式错误 |
| `10004` | 密码为空 |
| `10005` | 登录失败 |
| `10007` | 账号已存在 |
| `10010` | OAuth 未绑定 |
| `10011` | 用户不存在 |
| `20002` | Token 过期 |
| `20003` | Token 生成失败 |
| `20004` | Token 无效 |
| `20006` | Token 解析失败 |
| `20007` | Ticket 不正确 |
| `20008` | Ticket 不存在 |
| `30001` | 邮件发送失败 |
| `30002` | 验证码错误 |
| `30003` | 邮箱格式错误 |
| `40001` | 账号验证失败 |
| `40002` | 密码验证失败 |
| `50000` | 内部错误 |
| `60001` | OAuth 客户端错误 |
| `60002` | OAuth AccessToken 错误 |
| `60003` | OAuth RefreshToken 错误 |
| `70003` | 注册阶段错误 |
| `70004` | 重置密码失败 |
| `80000` | 用户资料不存在 |
| `80001` | 组织 ID 无效 |
| `80002` | 隐藏字段无效 |
| `90000` | 通知发送失败 |
| `90001` | 图片处理失败 |
| `90002` | 图片 URL 无效 |
| `10012` | OAuth 已绑定其他账号 | 该第三方账号已绑定到另一个用户 |
| `10013` | OAuth 绑定失败 | 绑定过程中 provider 返回错误 |
| `10014` | 解绑失败 | 解绑后无可用登录方式，或该 OAuth 未绑定 |
| `10015` | 邮箱已被注册 | OAuth 注册补全时邮箱已被占用 |
| `70005` | OAuth 注册补全失败 | 参数缺失或 Ticket 无效 |
| `10016` | `invalid_request` | OAuth 2.1 请求参数错误 |
| `10017` | `invalid_client` | OAuth 2.1 客户端认证失败 |
| `10018` | `invalid_grant` | OAuth 2.1 授权码或 Refresh Token 无效/过期 |
| `10019` | `unauthorized_client` | OAuth 2.1 客户端无权使用此授权类型 |
| `10020` | `unsupported_grant_type` | OAuth 2.1 不支持的授权类型 |
| `10021` | `invalid_scope` | OAuth 2.1 请求的 scope 无效/未授权 |
| `10022` | `server_error` | OAuth 2.1 授权服务端内部错误 |
| `10023` | `temporarily_unavailable` | OAuth 2.1 服务端暂时不可用 |

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
| SAST | 南京邮电大学校大学生科学技术协会 |

---

## 13. 已决策项

以下问题已在本 PRD 评审过程中确认：

| 问题 | 决策 | 说明 |
|------|------|------|
| 密码哈希 | 保持 SHA512 | 兼容老用户密码，登录时做好加密和安全验证 |
| 单设备登录 | 最多 5 设备 | Redis Sorted Set 管理，超出淘汰最旧设备 |
| OAuth2 客户端注册 | 开放注册 | 任何人可调用 `/oauth2/register` 创建客户端 |
| QQ 登录 | 不做 | 已舍去 |
| API 契约修改 | 仅在"极大优化"时修改 | 端点路径保持 `/api/v1/...`，认证 Header 不改 |
| 第一方登录 | 走标准 OAuth2 | 作为 public client，PKCE-S256，无 client_secret |
| Access Token 签名 | RS256 | 非对称签名，支持资源服务器独立验签 |
| 即时失效机制 | `token_version` | user 表加字段，改密时自增使所有 Token 失效 |

---

*文档版本 v1.1 | 最后更新 2026-05-24*
