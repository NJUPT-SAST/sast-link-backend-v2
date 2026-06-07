# SAST Link Backend v2 — 项目进度

> 最后更新：2026-06-07
> 最新提交：2026-06-07 `02317e4` — fix: docker-compose and .env alignment

---

## 总览

| 模块                                                        | 状态     | 详情                                         |
| ----------------------------------------------------------- | -------- | -------------------------------------------- |
| [项目基础](#1-项目基础)                                     | 已完成   | 脚手架、配置、数据库/Redis、日志             |
| [认证（Auth）](#2-认证auth)                                 | 部分完成 | 注册流程已完成；登录、改密、JWT 待实现       |
| [第三方 OAuth 登录](#3-第三方-oauth-登录)                   | 未开始   | GitHub / 飞书 OAuth 回调全链路               |
| [用户资料（Profile）](#4-用户资料profile)                   | 部分完成 | 查询/修改已完成；鉴权中间件、头像上传待补    |
| [第三方账号绑定（Identities）](#5-第三方账号绑定identities) | 未开始   | 绑定/解绑 GitHub、飞书、第三方邮箱           |
| [OAuth 2.1 + OIDC](#6-oauth-21--oidc)                       | 未开始   | 授权服务端、OIDC Provider、Discovery、JWKS   |
| [管理后台（Admin）](#7-管理后台admin)                       | 未开始   | 用户管理、OAuth 客户端管理、审计日志查询     |
| [基础设施与运维](#8-基础设施与运维)                         | 部分完成 | 健康检查、CI/CD 已完成；限流、审计运行时待补 |
| [测试](#9-测试)                                             | 部分覆盖 | config / domain / infra / response 已覆盖    |

---

## 1. 项目基础

| 子模块                                                            | 状态         |
| ----------------------------------------------------------------- | ------------ |
| [1.1 项目脚手架](#11-项目脚手架)                                  | 已完成       |
| [1.2 配置](#12-配置internalconfigconfiggo)                        | 已完成       |
| [1.3 数据库 / Redis 连接](#13-数据库--redis-连接internalinfra)    | 已完成       |
| [1.4 日志](#14-日志internalinfraloggo)                            | 已完成       |
| [1.5 统一响应信封](#15-统一响应信封internalpkgresponseresponsego) | 已完成       |
| [1.6 领域模型](#16-领域模型internaldomain)                        | 已完成       |
| [1.7 DTO 层](#17-dto-层internaldto)                               | 大部分已完成 |
| [1.8 数据访问层](#18-数据访问层internalrepository)                | 部分完成     |

### 1.1 项目脚手架

- 状态：已完成
- Go 1.26.4 + Gin v1.12 + GORM v1.31
- 标准 Go 项目布局：`cmd/api`、`internal/{config,domain,dto,handler,service,repository,infra,pkg}`
- Docker 多阶段构建 + docker-compose（API 仅含自身容器；接入服务器已有 PostgreSQL / Redis 实例，通过外部 bridge 网络 `postgres` + `redis` 通信）

### 1.2 配置（`internal/config/config.go`）

- 状态：已完成
- 全部配置组：App、DB、Redis、JWT（AccessTokenExpiry 1h + RefreshTokenExpiry 720h）、SMTP、CORS、OAuth（仅 Feishu + GitHub）、Storage（COS）、RateLimit
- 完全由环境变量驱动，均有默认值
- JWT 密钥为 RSA 私钥（PEM），通过 `JWT_SECRET_KEY` / `JWT_SECRET_KEY_PREV` 注入，支持 RS256 签名 + JWKS 密钥轮换
- 关键密钥非空校验（JWT_SECRET_KEY、DB_PASSWORD、REDIS_PASSWORD）

### 1.3 数据库 / Redis 连接（`internal/infra/`）

- 状态：已完成

| 文件       | 说明                                                 |
| ---------- | ---------------------------------------------------- |
| `db.go`    | PostgreSQL 连接（GORM），连接池 25/5/30min，健康检查 |
| `redis.go` | Redis 客户端，含 Ping 验证                           |

### 1.4 日志（`internal/infra/log.go`）

- 状态：已完成
- slog JSON handler，日志级别由配置控制（debug / info / warn / error）

### 1.5 统一响应信封（`internal/pkg/response/response.go`）

- 状态：已完成
- 所有非 OAuth 端点统一使用 `{"code": 0, "message": "ok", "data": {...}}`
- 错误码为 5 位数字 `{HTTP状态}{序号}`，HTTP 状态码由错误码自动推导
- 提供 `OK` / `Created` / `Err` / `ErrWithStatus` 四个快捷函数

### 1.6 领域模型（`internal/domain/`）

- 状态：已完成 — `docs/psql-db-design.md` 中 8 张核心表均有 GORM domain 模型覆盖，nullable 字段已按 DDL 用 pointer 表达

| 文件 | 说明 |
|------|------|
| `user.go` | `User` 实体（15 字段对齐 DDL；`student_id` 为 nullable `*string`） |
| `profile.go` | `Profile` 实体（11 字段对齐 DDL；展示字段与 `department` 均为 nullable） |
| `identity.go` | `Identity` 实体（`identities` 表，含 provider/provider_id 唯一约束、GitHub/Lark partial unique index tag） |
| `oauth_client.go` | `OAuthClient` 实体（`oauth_clients` 表，含 nullable `client_secret`、TEXT[] 数组字段） |
| `oauth_auth.go` | `OAuthAuthorization` 实体（`oauth_authorizations` 表；无 `updated_at`，对齐 DDL 生命周期） |
| `oauth_token.go` | `OAuthAccessToken` + `OAuthRefreshToken` 实体（Token 元数据、refresh token family/sequence） |
| `audit.go` | `AuditLog` 实体 + `AuditAction` 枚举（10 种操作类型；nullable 字段、`success default:true`、`err_code type:int` 已对齐） |
| `organize.go` | `Organize` 实体（3 字段全对齐） |
| `array.go` | `StringArray`，用于 PostgreSQL `TEXT[]` 字段（OAuth scopes / grant_types / redirect_uris） |
| `enums.go` | 7 种枚举：`UserRole`(4)、`Department`(2)、`LoginMethod`(3)、`UserState`(4)、`EmailType`(2)、`ClientType`(2)、`College`(20) |
| `errors.go` | `ErrCode`（35 个非零常量 + `Success=0`）、`AppError`、`NewError` / `WrapError` |

**后续缺口**：domain 层已补齐；下一步是为 identities / OAuth token/client/auth 表补 repository、service 和 handler。

### 1.7 DTO 层（`internal/dto/`）

- 状态：大部分已完成

| 文件         | 说明                                         | 状态                          |
| ------------ | -------------------------------------------- | ----------------------------- |
| `auth.go`    | 注册/登录/刷新/改密/重置密码 的请求/响应 DTO | Token 相关 DTO 已定义但未使用 |
| `profile.go` | 用户资料 DTO（含 IdentityData、ProfileData） | 已完成                        |
| `oauth.go`   | OAuth 回调/临时用户 DTO                      | 已定义但未使用                |
| `user.go`    | OAuth 注册补全/绑定 DTO                      | 已定义但未使用                |

### 1.8 数据访问层（`internal/repository/`）

- 状态：部分完成

| 接口/实现                           | 状态                                                                                                                        |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `UserRepository` + `userRepo`       | 已完成（FindByID / FindByLoginEmail / FindByStudentID / Create / Update / UpdatePassword / UpdateState / BumpTokenVersion） |
| `ProfileRepository` + `profileRepo` | 已完成（FindByUserID / Create / Update）                                                                                    |
| `OrganizeRepository`                | 接口已定义，无实现                                                                                                          |
| `IdentityRepository`                | 未创建                                                                                                                      |

---

## 2. 认证（Auth）

> 对应 PRD §4.1–§4.4、§4.6–§4.9；API 文档第 1 节。

| 子模块                                                               | 状态                     |
| -------------------------------------------------------------------- | ------------------------ |
| [2.1 注册](#21-注册postauthregistersend-code--verify-code--register) | 基本完成（JWT 签发待补） |
| [2.2 密码登录](#22-密码登录postuserlogin)                            | 未开始                   |
| [2.3 JWT 鉴权](#23-jwt-鉴权)                                         | 未开始                   |
| [2.4 Refresh Token 管理](#24-refresh-token-管理)                     | 未开始                   |
| [2.5 改密 / 重置密码](#25-改密--重置密码)                            | 未开始                   |
| [2.6 登出](#26-登出postauthlogout)                                   | 未开始                   |

### 2.1 注册（`POST /auth/register/send-code` → `verify-code` → `register`）

- 状态：基本完成（JWT 签发待补）

```
POST /auth/register/send-code      → 校验邮箱域名 → captcha.Generate → email.SendVerificationCode
POST /auth/register/verify-code    → captcha.Verify → 生成 Register-Ticket（Redis，5 分钟）
POST /auth/register                → GetDel 消费 Ticket → 校验 → PBKDF2 哈希 → 创建 user + profile
```

- 邮箱域名限制：仅 `@njupt.edu.cn` / `@sast.fun`
- 验证码：5 字符 base32（`S-XXXXX`），Redis key `sastlink:verify:{email}`，5 分钟 TTL
- Register-Ticket：`reg_` + 32 位 hex，`GetDel` 原子消费防重放
- 密码：PBKDF2-SHA512，60 万次迭代，16 字节随机盐，存储格式 `pbkdf2$<salt_hex>$<hash_hex>`
- 学院校验（无效值 fallback 到"其他"）、邮箱去重
- Profile 创建失败时的尽力回滚（软删除孤儿 User）

**待补**：

- `POST /auth/register` 返回空 Token（`""`）— JWT 服务未实现
- 注册时 OAuth 绑定（`RegistrationState` + `OAuthState` 处理为 TODO）
- 注册成功后写入 `audit_logs`

### 2.2 密码登录（`POST /user/login`）

- 状态：未开始
- DTO `LoginRequest` 已定义（`login_email` + `password`）
- PRD 要求：查 user / identities → 检查登录失败次数（Redis 15min 窗口 ≥ 10 次锁定）→ PBKDF2 校验 → 检查账号状态 → 设备数管理 → 签发 Token Pair → 写审计日志
- 注意：第三方邮箱（`other_mail`）登录需查 `identities` 表反查 user_id，此路径依赖 `IdentityRepository`。可先实现教育邮箱登录（直查 `user.login_email`），第三方邮箱登录作为后续增强

### 2.3 JWT 鉴权

- 状态：未开始
- PRD 要求：RS256 签名 Access Token（claims 含 jti / sub / role / state / token_version / scopes），有效期 1h
- `currentUserID()` 占位函数当前从 `c.Get("userID")` 读取，无任何代码写入该值
- JWT 中间件待实现：提取 userID → 验证签名 → 检查 jti 黑名单（Redis）→ 校验 token_version（Redis 缓存，未命中回源 DB）→ 检查账号状态

### 2.4 Refresh Token 管理

- 状态：未开始
- DTO 已定义：`RefreshTokenRequest`、`LogoutRequest`、`TokenRefreshResponse`
- PRD 要求：opaque 随机字符串，HMAC-SHA256 hash 存 DB，30 天有效期，rotation + family 链机制

### 2.5 改密 / 重置密码

| 事项                                                                                                                    | 状态   |
| ----------------------------------------------------------------------------------------------------------------------- | ------ |
| `POST /auth/change-password` — 需旧密码，新密码 ≥ 8 位，成功后 token_version 自增（DTO `ChangePasswordRequest` 已定义） | 未开始 |
| `POST /auth/forgot-password/send-code` — 发送重置密码验证码（复用 `SendCodeRequest`）                                   | 未开始 |
| `POST /auth/reset-password` — 验证码校验 → 新密码哈希 → token_version 自增（DTO `ResetPasswordRequest` 已定义）         | 未开始 |
| 改密/重置后撤销所有旧 Token（token_version 自增 + jti 黑名单）                                                          | 未开始 |

### 2.6 登出（`POST /auth/logout`）

- 状态：未开始
- DTO `LogoutRequest` 已定义
- PRD 要求：Access Token jti 写入 Redis 黑名单（TTL = 剩余有效期），Refresh Token family 链全部撤销

---

## 3. 第三方 OAuth 登录

> 对应 PRD §4.5；API 文档第 2 节。

| 子模块                                                 | 状态   |
| ------------------------------------------------------ | ------ |
| [3.1 GitHub 登录](#31-github-登录)                     | 未开始 |
| [3.2 飞书登录](#32-飞书登录)                           | 未开始 |
| [3.3 交换登录码](#33-交换登录码postoauthexchange-code) | 未开始 |

### 3.1 GitHub 登录

| 事项                                                                                  | 状态   |
| ------------------------------------------------------------------------------------- | ------ |
| `GET /oauth/github` — 重定向至 GitHub OAuth 授权页                                    | 未开始 |
| `GET /oauth/github/callback` — 用 code 换 access_token → 查 identities 判断是否已绑定 | 未开始 |
| 已有绑定分支 — 签发 `login_code`（Redis，60s）→ 302 前端 `?code=<login_code>`         | 未开始 |
| 无绑定分支 — 生成 `registration_state`（Redis，15min）→ 302 注册补全页                | 未开始 |

### 3.2 飞书登录

| 事项                                                                | 状态   |
| ------------------------------------------------------------------- | ------ |
| `GET /oauth/lark` — 重定向至飞书 OAuth 授权页                       | 未开始 |
| `GET /oauth/lark/callback` — 用 code 换 access_token → 获取用户信息 | 未开始 |
| SAST 企业校验（tenant_key），非 SAST 用户拒绝（40302）              | 未开始 |
| 已有绑定 / 无绑定分支（同 GitHub）                                  | 未开始 |

### 3.3 交换登录码（`POST /oauth/exchange-code`）

- 状态：未开始
- DTO `ExchangeCodeRequest` 已定义
- 用 OAuth 回调中的一次性 `login_code` 换取 Token Pair（GetDel 原子消费）

---

## 4. 用户资料（Profile）

> 对应 PRD §2.1（个人卡片）；API 文档第 3 节。

| 子模块                       | 状态     |
| ---------------------------- | -------- |
| [4.1 查询资料](#41-查询资料) | 部分完成 |
| [4.2 修改资料](#42-修改资料) | 部分完成 |
| [4.3 上传头像](#43-上传头像) | 未开始   |

### 4.1 查询资料

- 状态：部分完成
- 已实现：查询 user + profile 并组装为 `UserProfileData`
- 待补：`Identities` 始终返回 `[]` — `IdentityRepository` 不存在；JWT 中间件替换 `currentUserID()` 占位

### 4.2 修改资料

- 状态：部分完成
- 已实现：部分更新 user 表（name / phone_number / qq_number / student_id / college / major）和 profile 表（nickname / department / intro / email / blog_url / github_url）
- `UpdateProfile` 若 profile 行不存在则自动创建
- 头像（`avatar`）通过独立端点 `PUT /user/avatar` 上传，不走此接口（PRD §4.9）
- 待补：无审计日志写入；College / Department 校验在 service 层重复（DB 层也有限制）

### 4.3 上传头像

- 状态：未开始
- PRD 要求：multipart/form-data，限制 5MB，格式 jpg/png/webp，上传至腾讯云 COS
- DTO `UploadAvatarResponse` 已定义

---

## 5. 第三方账号绑定（Identities）

> 对应 PRD §2.1（第三方绑定）；API 文档第 4 节。

| 子模块                                              | 状态   |
| --------------------------------------------------- | ------ |
| `IdentityRepository` 接口 + 实现                    | 未开始 |
| `GET /user/identities` — 查看绑定列表               | 未开始 |
| `POST /user/identities/lark` — 绑定飞书             | 未开始 |
| `POST /user/identities/github` — 绑定 GitHub        | 未开始 |
| `POST /user/identities/email` — 发起绑定邮箱        | 未开始 |
| `POST /user/identities/email/verify` — 确认绑定邮箱 | 未开始 |
| `DELETE /user/identities/:id` — 解绑                | 未开始 |

- `IdentityRepository` 接口与实现均未创建
- 领域模型 `domain.Identity` 已创建；当前组件链缺口从 repository 开始：repository → service → handler
- DB 表 `identities` 已在 `docs/psql-db-design.md` 中完整设计（含约束、索引、触发器）
- OAuth 注册绑定流程（`registration_state` + `oauth_state`）依赖 identities 写入能力，参见 PRD §4.5

---

## 6. OAuth 2.1 + OIDC

> 对应 PRD §3.1（认证授权）、§4.2、§4.10–§4.12；API 文档第 5 节、第 8 节。

| 子模块                                                                                                        | 状态                   |
| ------------------------------------------------------------------------------------------------------------- | ---------------------- |
| [6.1 授权端点](#61-授权端点)（authorize / token / revoke）                                                    | 未开始                 |
| [6.2 OIDC Provider](#62-oidc-provider)（Discovery / JWKS / UserInfo）                                         | 未开始                 |
| [6.3 数据表](#63-数据表)（oauth_clients / oauth_authorizations / oauth_access_tokens / oauth_refresh_tokens） | DDL + domain 已完成，repository/service 未开始 |
| 密钥管理（RS256 双密钥轮换，`JWT_SECRET_KEY` + `JWT_SECRET_KEY_PREV`）                                        | 设计已完成             |

### 6.1 授权端点

| 事项                                                                                          | 状态   |
| --------------------------------------------------------------------------------------------- | ------ |
| `GET /oauth/authorize` — 授权端点（PKCE-S256 强制，state 强制，可选 nonce）                   | 未开始 |
| `POST /oauth/token` — Token 端点（authorization_code grant，校验 code / PKCE / redirect_uri） | 未开始 |
| `POST /oauth/token` — refresh_token grant（旋转 + family 链）                                 | 未开始 |
| `POST /oauth/token` — scope 含 openid 时返回 id_token（RS256 JWT）                            | 未开始 |
| `POST /oauth/revoke` — Token 撤销（family 链级联）                                            | 未开始 |
| 第一方应用 PKCE 认证（无 client_secret）                                                      | 未开始 |
| 第三方应用 client_secret_post 认证                                                            | 未开始 |
| 授权码一次性使用 + 重放检测（family_id 级联撤销）                                             | 未开始 |

### 6.2 OIDC Provider

| 事项                                                                                      | 状态   |
| ----------------------------------------------------------------------------------------- | ------ |
| `GET /.well-known/openid-configuration` — OIDC Discovery 元数据                           | 未开始 |
| `GET /.well-known/jwks.json` — JWKS 公钥分发                                              | 未开始 |
| `GET /userinfo` / `POST /userinfo` — OIDC UserInfo 端点                                   | 未开始 |
| ID Token claims 签发（iss / sub / aud / exp / iat / auth_time / nonce / name / email 等） | 未开始 |

### 6.3 数据表

| 事项                                                                 | 状态       |
| -------------------------------------------------------------------- | ---------- |
| `oauth_clients` — 客户端注册表                                       | DDL + domain 已完成 |
| `oauth_authorizations` — 授权码表                                    | DDL + domain 已完成 |
| `oauth_access_tokens` — Access Token 元数据表                        | DDL + domain 已完成 |
| `oauth_refresh_tokens` — Refresh Token 表（含 family_id + sequence） | DDL + domain 已完成 |
| pg_cron 定时清理过期授权码 / Token / Refresh Token                   | DDL 已完成 |

---

## 7. 管理后台（Admin）

> 对应 PRD §2.2；API 文档第 6 节。

| 子模块                                       | 状态   |
| -------------------------------------------- | ------ |
| [7.1 用户管理](#71-用户管理)                 | 未开始 |
| [7.2 OAuth 客户端管理](#72-oauth-客户端管理) | 未开始 |
| [7.3 审计日志查询](#73-审计日志查询)         | 未开始 |

- 所有端点均已在 API 文档和 OpenAPI 规范中定义

### 7.1 用户管理

| 事项                                                                                                     | 状态   | 角色要求         |
| -------------------------------------------------------------------------------------------------------- | ------ | ---------------- |
| `GET /admin/users` — 用户列表（分页 / role / state / department / college / keyword 筛选）               | 未开始 | admin / lecturer |
| `GET /admin/users/:id` — 用户详情                                                                        | 未开始 | admin / lecturer |
| `PUT /admin/users/:id` — 编辑用户信息（name / phone / qq / student_id / college / major / role / state） | 未开始 | admin            |
| `DELETE /admin/users/:id` — 软删除（state → is_deleted，级联撤销 Token）                                 | 未开始 | admin            |
| `PUT /admin/users/:id/restore` — 恢复已注销用户（state → njupter）                                       | 未开始 | admin            |
| admin / lecturer 角色鉴权中间件                                                                          | 未开始 | —                |

### 7.2 OAuth 客户端管理

| 事项                                                                                   | 状态   | 角色要求 |
| -------------------------------------------------------------------------------------- | ------ | -------- |
| `GET /admin/oauth-clients` — OAuth 客户端列表                                          | 未开始 | admin    |
| `POST /admin/oauth-clients` — 注册 OAuth 客户端（自动生成 client_id + client_secret）  | 未开始 | admin    |
| `PUT /admin/oauth-clients/:id` — 更新 OAuth 客户端（name / redirect_uris / is_active） | 未开始 | admin    |

### 7.3 审计日志查询

| 事项                                                                               | 状态   | 角色要求 |
| ---------------------------------------------------------------------------------- | ------ | -------- |
| `GET /admin/audit-logs` — 分页查询（按 user_id / action / resource / success / 时间范围筛选） | 未开始 | admin    |

---

## 8. 基础设施与运维

| 子模块                                         | 状态     |
| ---------------------------------------------- | -------- |
| [8.1 健康检查](#81-健康检查gethealth)          | 已完成   |
| [8.2 审计日志（运行时）](#82-审计日志运行时)   | 部分完成 |
| [8.3 幂等性](#83-幂等性)                       | 部分完成 |
| [8.4 限流](#84-限流)                           | 未开始   |
| [8.5 数据库迁移](#85-数据库迁移docsmigrations) | 部分完成 |
| [8.6 CI/CD](#86-cicd)                          | 已完成   |
| [8.7 文档](#87-文档)                           | 已完成   |

### 8.1 健康检查（`GET /health`）

- 状态：已完成
- 返回 `{"status": "ok|degraded", "db": "ok|fail", "redis": "ok|fail"}`

### 8.2 审计日志（运行时）

- 状态：部分完成
- 领域模型已完成（`AuditLog` 实体 + 10 种 `AuditAction`）
- handler / service 中无任何写入调用 — 注册、登录、资料更新等均不写审计日志
- DB 迁移 `000001_audit_logs_enhance` 已编写（复合索引 + pg_cron 90 天清理），待应用

### 8.3 幂等性

- 状态：部分完成
- `IdempotencyStore` 接口 + `RedisIdempotencyStore` 已实现（24h TTL）
- API 层未接入（无中间件 / handler 集成）

### 8.4 限流

- 状态：未开始
- 配置已定义（`RateLimitConfig`：global_rps / login_rpm / send_email_rpm / captcha_rpm / register_rph）
- 限流中间件未实现

### 8.5 数据库迁移（`docs/migrations/`）

| 迁移脚本                          | 说明                                                          | 是否已应用 |
| --------------------------------- | ------------------------------------------------------------- | ---------- |
| `000001_audit_logs_enhance`       | 新增复合索引 + pg_cron 90 天清理任务                          | 待确认     |
| `000002_rename_state_enum_values` | 重命名 `on-sast` → `on_sast`，`retired-sast` → `retired_sast` | 待确认     |

> 完整 DDL（枚举、表、函数、触发器、pg_cron）位于 `docs/psql-db-design.md`，尚未拆分为可执行的迁移文件。

### 8.6 CI/CD

- 状态：已完成

| 工作流   | 触发条件           | 内容                                                                                                   |
| -------- | ------------------ | ------------------------------------------------------------------------------------------------------ |
| CI       | push / PR to main  | lint（golangci-lint v2 + gofmt）→ vet → build（含 race）→ test（含 race + coverage）→ go mod tidy 检查 |
| Security | push / PR / 每周一 | gosec + govulncheck                                                                                    |

- Docker 多阶段构建（`docker/Dockerfile`）

### 8.7 文档

- 状态：已完成

| 文件                       | 说明                                                      |
| -------------------------- | --------------------------------------------------------- |
| `docs/API文档.md`          | 完整 API 参考（中文）                                     |
| `docs/SAST Link v2 PRD.md` | 产品需求文档                                              |
| `docs/openapi.yaml`        | OpenAPI 3.0.1 规范（v2.0.0）                              |
| `docs/psql-db-design.md`   | 完整数据库设计（7 个枚举、8 张表、函数、触发器、pg_cron） |

---

## 9. 测试

| 包               | 测试文件              | 覆盖内容                                                 | 状态       |
| ---------------- | --------------------- | -------------------------------------------------------- | ---------- |
| `config`         | `config_test.go`      | 默认值加载、自定义值、缺失密钥、DSN、Addr、工具函数      | 已覆盖     |
| `domain`         | `errors_test.go`, `array_test.go` | AppError.Error/Unwrap、NewError、WrapError、错误码唯一性；StringArray PostgreSQL TEXT[] 映射 | 已覆盖     |
| `infra`          | `db_test.go`          | 无效 DSN、DSN 格式、空指针健康检查                       | 已覆盖     |
| `infra`          | `redis_test.go`       | 已有                                                     | 已覆盖     |
| `infra`          | `log_test.go`         | 已有                                                     | 已覆盖     |
| `infra`          | `idempotency_test.go` | 已有                                                     | 已覆盖     |
| `pkg/response`   | `response_test.go`    | OK、Created、Err、ErrWithStatus、JSON 标签、MessageData  | 已覆盖     |
| **`handler`**    | —                     | —                                                        | **无测试** |
| **`service`**    | —                     | —                                                        | **无测试** |
| **`repository`** | —                     | —                                                        | **无测试** |
| **`dto`**        | —                     | —                                                        | **无测试** |

---

## 10. 实现优先级

### 总体路线（PRD §11）

1. 用户认证 — 注册 / 登录 / JWT 签发验证 / 验证码 / 改密 / 重置密码 / 登出
2. 用户资料管理 — 查看 / 编辑 / 头像上传
3. OAuth 登录 — GitHub / 飞书 回调 + login_code 交换
4. OAuth 绑定 / 解绑 + 注册补全 — registration_state + oauth_state 双重校验
5. 限流与防刷中间件
6. 审计日志 + 健康检查
7. 头像内容审核（腾讯云 COS）
8. OAuth 2.1 授权服务端 — authorize / token / revoke + PKCE
9. OIDC Provider — discovery / JWKS / UserInfo / ID Token
10. OAuth 客户端注册 API
11. 管理后台 — 用户管理 / OAuth 客户端管理 / 审计日志查询
12. pg_cron 定时清理
13. 个人卡片页面
14. 测试、联调、上线

### 当前冲刺：第 1 步「用户认证」分解

> 第 1 步内部依赖链：JWT 服务 → JWT 中间件 → 密码登录 → Refresh Token → 改密/重置密码 → 登出。
> 第三方邮箱登录依赖 identities 表（第 4 步），可先实现教育邮箱登录再补。

1. **JWT 服务** — RS256 签名/验签，密钥轮换支持（`JWT_SECRET_KEY` + `JWT_SECRET_KEY_PREV`）
2. **JWT 中间件** — 替换 `currentUserID()` 占位，校验签名 → jti 黑名单 → token_version → 账号状态
3. **密码登录** — `POST /user/login`（教育邮箱路径，不含第三方邮箱）
4. **Refresh Token 旋转** — opaque token + HMAC-SHA256 hash + family 链 + rotation 检测
5. **改密 / 重置密码** — token_version 自增 + jti 黑名单撤销
6. **登出** — jti 黑名单 + family 链撤销
7. **数据库事务** — 替换 `Register()` 中的尽力回滚，同时覆盖登录 Token 签发路径
8. **Service / Repository 层测试** — 当前测试覆盖最大缺口

> 第 1 步完成后，教育邮箱注册+登录闭环可走通，再进入第 2 步（资料管理）和第 3-4 步（OAuth + identities）。
