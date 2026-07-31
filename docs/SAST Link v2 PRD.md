# SAST Link v2 PRD

## 1. 背景

### 1.1 定位

SAST Link 是南京邮电大学校大学生科学技术协会（SAST）的统一身份认证中心与人员信息管理系统。

### 1.2 目标

作为 SAST 基础设施的统一身份认证中心：
- 对内：提供密码 / GitHub / 飞书 多种登录方式，统一 SAST 内部应用的认证入口
- 对外：作为 OAuth 2.1 授权服务 + OIDC Provider，向第三方应用提供标准化认证

---

## 2. 功能需求

### 2.1 用户端

| 模块 | 功能 |
|------|------|
| 账号注册 | 使用 `@njupt.edu.cn` 或 `@sast.fun` 邮箱注册；注册流程两步（验证码 → 补充信息）；可选通过 OAuth 回调的 `registration_state` 同时绑定第三方账号 |
| 账号登录 | 邮箱密码登录；GitHub OAuth 登录；飞书 OAuth 登录（限 SAST 企业内用户） |
| 第三方绑定 | 已登录用户可绑定 GitHub / 飞书 / 第三方邮箱（最多 2 个）；绑定后可对应方式登录 |
| 账号管理 | 登出、改密（需旧密码）、重置密码（邮箱验证码）；修改个人资料；上传头像 |
| 个人卡片 | 生成公开个人主页链接（`https://link.sast.fun/card/{id}`），用于 homepage 友链展示 |

### 2.2 管理端

| 模块 | 功能 | 角色要求 |
|------|------|----------|
| 用户管理 | 用户列表（分页/筛选/搜索）、查看详情、编辑信息、软删除、恢复已注销用户 | admin / lecturer（只读）；admin（写） |
| OAuth 客户端管理 | 注册/查看/更新/停用 OAuth 客户端 | admin |
| 审计日志 | 分页查询，按用户/操作/时间/成功状态筛选 | admin |
| 限流与防刷 | 全局 + 按端点 + 按 IP 的多级限流中间件 | — |
| 头像内容审核 | 接入腾讯云 COS 内容审核（后期） | — |

---

## 3. 技术架构

### 3.1 技术栈

| 层 | 技术 | 细节 |
|---|---|------|
| 语言 | Go | 1.26.5 |
| Web 框架 | Gin | v1.12.0 |
| ORM | GORM | v1.31.1 |
| 数据库 | PostgreSQL | 16+（生产直连已有部署，开发用 Docker） |
| 缓存 | Redis | 8+ |
| 对象存储 | 腾讯云 COS | 头像上传 |
| 邮件 | SMTP | 验证码发送 |
| 密码哈希 | PBKDF2-SHA512 | 600,000 轮，16 字节随机盐。Go 标准库 `crypto/pbkdf2` + `crypto/sha512`，零外部依赖。单次派生约 380ms（16 核实测），并发上限 `PASSWORD_HASH_MAX_CONCURRENT`（默认 64）。派生排队可被 context 取消，客户端断开即释放队列位，避免无界积压 |
| 认证授权 | OAuth 2.1 + RS256 | JWT（Access Token）含 `kid` 头，支持密钥轮换；通过 JWKS 端点分发公钥 |
| 集成测试 | testcontainers-go | — |

### 3.2 密钥管理

| 密钥类型 | 存储方式 | 轮换策略 |
|----------|----------|----------|
| JWT 签名密钥 (RS256) | 环境变量 / Secret Manager | 支持双密钥（`JWT_SECRET_KEY` + `JWT_SECRET_KEY_PREV`）；active 必须为 RSA private PEM，新 Token 用 active key 签名；previous 可为 RSA public/private PEM，仅用于验签，过渡期后废弃 |
| OAuth client_secret | DB 存储 bcrypt hash | 可随时重置，不影响已签发 Token |

### 3.3 部署架构

- **容器化**：Docker 多阶段构建（golang:alpine → alpine），复用服务器上已有的 PostgreSQL 与 Redis 实例
- **高可用**：API 服务无状态（JWT 自包含），可水平扩展；黑名单仅是快速拒绝路径，`oauth_access_tokens.revoked_at` 每请求经 DB 校验，Redis 黑名单不一致不影响吊销正确性；设备记录在扩缩容时短暂不一致可接受。PostgreSQL 是唯一必需依赖，Redis 故障时服务降级但仍可提供认证能力（见 §6.0）
- **定时任务**：pg_cron 在 PG 内部调度清理过期数据，无多实例重复执行问题
- **Base URL**：`https://link.sast.fun/v2`

---

## 4. 功能详细设计

### 4.1 内部认证（SAST Link 内部）

SAST Link 内部使用 JWT RS256 签名 Access Token + opaque Refresh Token：

- **Access Token**：RS256 签名 JWT，有效期 1 小时，含 `jti`（撤销）、`sub`（user.id）、`role`、`state`、`token_version`、`scope`、`azp`（签发对象 client_id）等 claims。自包含，业务服务可离线验签
- **Refresh Token**：opaque 随机字符串，有效期 30 天，HMAC-SHA256 hash 后存 DB。采用 **rotation + family 链** 机制（见 4.6）
- **登录态校验**：每次请求校验 Access Token 签名 → 检查 jti 是否在黑名单（Redis）→ 单条 SQL join `oauth_access_tokens` 与 `user`，一次取回 `revoked_at`/`expires_at`/`state`/`role`/`token_version`，校验 token 未撤销未过期、账号非 is_deleted、`token_version` 与 claims 一致 → 校验 `azp` 为内置 first-party 客户端（见 §7.1「第三方 Token 隔离」）
- **角色鉴权**：角色判定读上述查询取回的 DB `role`，而非 Access Token 里的 `role` claim。claim 是签发时快照，降权后旧 token 仍带原角色；读 DB 使降权在下一个请求即生效，与 `token_version` 机制正交（后者依赖改 role 时同事务递增，见 §4.12）。`role` claim 仍参与非空校验，但不用于授权决策
- **登出**：Access Token 的 jti 写入 Redis 黑名单（TTL = 剩余有效期）；Refresh Token family 链全部撤销（`revoked_at` = NOW）
- **改密**：`user.token_version` 自增，拦截所有旧 token

### 4.2 对外认证（OAuth 2.1 + OIDC Provider）

SAST Link 同时作为 OAuth 2.1 授权服务器和 OIDC Provider：

| 层面 | 标准 | 说明 |
|------|------|------|
| 授权框架 | OAuth 2.1 | PKCE-S256 强制（即使第三方应用），state 参数强制 |
| 身份层 | OpenID Connect | 当 scope 含 `openid` 时返回 ID Token（RS256 JWT） |
| 客户端认证 | PKCE（第一方）/ client_secret_post（第三方） | 第一方应用无 client_secret；第三方应用注册后获取 client_secret（bcrypt 存储） |
| 端点 | authorize / token / revoke / userinfo / jwks / discovery | 详见 4.10 / 4.11 |

### 4.3 注册流程

**两步注册**：

1. `POST /auth/register/send-code` → 校验邮箱域名 → 生成 6 位数字验证码 → SMTP 发送 → 验证码写 Redis（key: `sastlink:verify:register:{email}`，TTL 5min）
2. `POST /auth/register/verify-code` → 校验验证码（匹配后删除；填错仅消耗一次尝试，验证码保留，最多 5 次后作废）→ 返回 Register-Ticket（`reg_` + 32 位 hex，Redis 5min，一次性）
3. `POST /auth/register` → 凭 Register-Ticket 获取已验证邮箱（先只读校验）→ 校验所有 user 字段已填且密码 ≥ 8 位 → 查邮箱/学号是否被占用 → PBKDF2-SHA512 哈希 → 创建 user + profile → 建号成功后才 DEL 消费 ticket → 签发 Token Pair

并发注册由 `user.login_email` 的 UNIQUE 约束串行化，不依赖 ticket 消费选主；因此 ticket 保留到建号成功为止，竞态失败者（40901/40902）可改字段后用同一 ticket 重试，无需重新发验证码。`user` 表有 `login_email` 与 `student_id` 两个 UNIQUE 约束，唯一冲突需按约束名区分后再映射错误码，否则学号冲突会被误报为「邮箱已被注册」

**可选 registration_state 绑定**：传入 `registration_state` + `oauth_state`（OAuth 标准 state 参数）时，注册成功后 * 并消费 `registration_state` + `oauth_state` → 验证双值匹配 → 自动创建 identities 记录。用于第三方 OAuth 首次登录的无绑定分支——用户先经 OAuth 回调拿到 `registration_state`，再走注册流程，注册后自动绑定

**约束**：
- 注册邮箱域名仅限 `@njupt.edu.cn` / `@sast.fun`
- PG 触发器 `auto_set_email_type` 自动根据域名设置 `email_type`
- 学号唯一（`student_id UNIQUE`），重复注册返回 40902

### 4.4 密码登录

```
POST /user/login
```

**流程**：
1. 校验邮箱格式 — `@njupt.edu.cn` / `@sast.fun` 查 `user.login_email`；第三方邮箱查 `identities(provider='other_mail').provider_id` 反查 user
2. 检查登录失败次数（Redis `sastlink:auth:login_failure:{email}`，15min 窗口 ≥ 10 次则锁定）
3. 查用户是否存在：不存在返回 40106（邮箱不存在）；存在则执行 PBKDF2-SHA512 密码哈希校验
4. 校验账号状态 — `is_deleted` 拒绝（40301）
5. 检查设备数 — 该用户已有设备数 ≥ 5 时淘汰最旧设备
6. 生成 Token Pair，Redis 记录设备信息
7. DB 写入 `oauth_refresh_tokens`、`oauth_access_tokens` 元数据、`audit_logs`

**token_version 机制**：`token_version` 存储在 `user` 表，改密/重置密码后递增。JWT Access Token 的 claims 中包含 `token_version`，登录态校验时与 DB 当前值比对，不一致即拒绝。此机制确保改密后所有旧 Token（无论是否在黑名单中）立即失效。

`token_version` 以 DB 为唯一权威，不单独走 Redis 缓存：中间件每请求本就需要查 `oauth_access_tokens` 拿 `revoked_at`/`expires_at`，`token_version` 由同一条 join `user` 的查询顺带返回，额外缓存只会在 DB 查询之外多一次网络往返而省不掉任何 DB 调用。若后续要削减这次 DB 查询，应缓存整个 auth state（`revoked_at` + `expires_at` + `state` + `token_version`）而非单个字段，并同步设计登出、family 级联撤销、改密与账号注销四条路径的缓存失效。

### 4.5 第三方 OAuth 登录

#### GitHub / 飞书 登录回调分支

```
GET /oauth/github/callback?code=...&state=...
GET /oauth/lark/callback?code=...&state=...
```

**已有绑定用户**：签发一次性 `login_code`（`lc_` + 32 位 hex，Redis，60s），302 重定向至前端 `?code=<login_code>`，前端调用 `POST /oauth/exchange-code` 换取 Token Pair

**无绑定用户**：
1. 生成 `registration_state`（Redis，15min，暂存 `provider` + `provider_id` + `identity_data` + `oauth_state`），其中 `oauth_state` 为原始 OAuth 回调的 CSRF `state` 参数
2. 302 重定向至注册补全页 `?registration_state=<registration_state>&oauth_state=<oauth_state>&provider=xxx&name=xxx&avatar=xxx`
3. 用户在注册补全页完成注册，`POST /auth/register` 时传入 `registration_state` + `oauth_state`（两者均从回调重定向的 URL 取）

   > 实现修正：`oauth_state` 由回调一并下发，而非「前端在跳转链中保留」。发起登录的页面在跳转到 provider 时已被卸载，回调是一次全新的顶层导航，前端没有任何途径仍然持有那个 state（本服务不设 cookie）。这不削弱双重绑定：其目的是让单独泄露的 `registration_state`（被分享的 URL、日志、referrer）不可兑换，而能读到这次回调重定向的攻击者本就同时掌握两个值。
4. 服务端 GetDel 消费 `registration_state`，校验其内的 `oauth_state` 与传入的 `oauth_state` 匹配 → 注册成功 + 自动创建 identities 绑定

**安全约束 — 防账号接管**：
- 飞书登录仅限 SAST 企业内用户（校验 tenant_key），非 SAST 企业用户拒绝（40302）
- `registration_state` 仅能用于新建用户注册绑定，**不可**用于已存在用户的追加绑定——已存在用户的绑定必须走 `POST /user/identities/*` 接口（需登录态）
- `registration_state` 为 GetDel 一次性消费，与 Register-Ticket/Bind-Ticket 一致，防重放
- `registration_state` 与原始 OAuth `state` 参数 **双重绑定**：消费时校验 Redis 中暂存的 `oauth_state` 与请求传入值匹配，即使 `registration_state` 泄露，没有对应的 OAuth `state` 也无法滥用
- 回调 state 参数强制校验，防 CSRF

### 4.6 Token 管理

| Token 类型 | 格式 | 有效期 | 说明 |
|------------|------|--------|------|
| Access Token | RS256 JWT | 1h | 自包含，含 jti/sub/role/state/token_version/scope/azp；kid 支持密钥轮换 |
| Refresh Token | opaque string | 30d | HMAC-SHA256 hash 存 DB（`oauth_refresh_tokens.token_hash`） |
| Register-Ticket | opaque string (`reg_` 前缀) | 5min | Redis 存储，一次性使用 |
| login_code | opaque string (`lc_` 前缀) | 60s | Redis 存储，一次性使用，OAuth 回调交换用 |
| registration_state | opaque string (`rs_` 前缀) | 15min | Redis 存储，GetDel 一次性消费。暂存 `{provider, provider_id, identity_data, oauth_state}`，消费时校验 OAuth state 匹配 |
| Bind-Ticket | opaque string (`be_` 前缀) | 5min | Redis 存储，一次性使用，待绑定邮箱地址内嵌 |
| Authorization Code | opaque string | 5min | DB 存储（`oauth_authorizations`），一次性使用 |

#### Refresh Token Rotation & 重放检测

```
Refresh Token Family 链：
family_id (UUID) ─── seq=0 (初始) ──rotated──► seq=1 ──rotated──► seq=2
```

- 合法用户刷新：旧 refresh_token 标记 revoked，签发新 token（family_id 不变，seq+1）
- 攻击者重放已 revoked 的 refresh_token：通过 family_id 检测到 seq 不连续 → **整条 family 链全部撤销**（级联撤销所有同 family_id 的 access_token + refresh_token），强制用户重新登录
- 过期处理：refresh_token 过期（`expires_at`）即失效，须重新登录，无宽限期

#### 登出

```
POST /auth/logout
Authorization: Bearer <access_token>
Body: { "refresh_token": "rt_..." }
```

- 当前 access_token 的 jti 写入 Redis 黑名单（TTL = 剩余有效期）
- 整条 refresh_token family 标记 revoked
- 仅删除当前设备记录（`ZREM` + `DEL`），不影响其他设备

### 4.7 密码管理

#### 修改密码（已知旧密码）

```
POST /auth/change-password
Authorization: Bearer <access_token>
Body: { "old_password", "new_password" }
```

- 验证旧密码正确
- 新密码 ≥ 8 位（NIST SP 800-63B 建议最小长度，不做强制复杂度，前端引导用户设置强密码）
- `user.token_version` 递增，级联撤销该用户所有 token family
- 当前 access_token jti 写入 Redis 黑名单

#### 重置密码（忘记密码）

```
POST /auth/forgot-password/send-code  →  发送验证码到注册邮箱
POST /auth/reset-password             →  校验验证码 + 新密码
```

- `POST /auth/forgot-password/send-code`：对格式合法且未触发限流的邮箱统一返回“已受理”。请求进入有界内存队列，worker 再查账号并只向已注册邮箱发送验证码。响应不暴露账号是否存在，也不保证邮件已经送达；队列满或进程重启时任务可能丢失，用户可在限流窗口后重试
- `POST /auth/reset-password`：校验验证码 + 新密码；账号不存在同样返回 40106
- 验证码正确后 `user.token_version` 递增，撤销所有 Token，设备记录清除
- 登录失败计数器清零

#### 登录锁定策略

- 同一邮箱 15min 内登录失败 ≥ 10 次 → 锁定
- 锁定自动过期（Redis key TTL 15min），超时后自动解锁
- 管理员可通过重置密码流程主动解锁

### 4.8 第三方账号绑定

#### 已登录用户绑定

| 绑定类型 | 端点 | 方式 | 约束 |
|----------|------|------|------|
| 飞书 | `POST /user/identities/lark?code=xxx` | 飞书 OAuth 授权码 | 每用户 1 个飞书；每飞书账号 1 个用户；限 SAST 企业用户 |
| GitHub | `POST /user/identities/github?code=xxx` | GitHub OAuth 授权码 | 每用户 1 个 GitHub；每 GitHub 账号 1 个用户 |
| 第三方邮箱 | `POST /user/identities/email` → `POST /user/identities/email/verify` | 两步：获取 Bind-Ticket → 验证码确认 | 每用户最多 2 个；`provider='other_mail'`；provider_id = 邮箱地址 |

#### 解绑

```
DELETE /user/identities/:id
Body: { "password": "current_password" }
```

- 必须输入当前密码二次确认
- 主邮箱（`user.login_email`）不在 identities 中，不可通过此接口解绑
- 该约束由数据库保证：V005 在 `user` 与 `identities` 两侧各建一个 BEFORE 触发器，禁止同一地址同时作为主邮箱与 `other_mail` 绑定存在。两列的 UNIQUE 各自只覆盖本表，应用层预检查挡不住并发（两个未提交事务互相不可见），故触发器内先按地址取 `pg_advisory_xact_lock` 串行化。违反时抛 `unique_violation`，约束名为 `ck_user_login_email_not_identity` / `ck_identities_provider_id_not_login_email`

- 解绑限流：Redis `sastlink:ratelimit:user:{user_id}:unbind`，60s 窗口内最多 3 次，在密码校验**之前**检查（见 §6 键表）
- 不属于当前用户的绑定 ID 与不存在的 ID 均返回 40400，避免探测他人绑定记录
- 「唯一登录方式」判定：持有 `login_email` 的账号恒可解绑任意 identity；仅靠 identity 登录的账号在解绑最后一条时被拒（42200）

### 4.9 用户资料

#### 字段归属

| 表 | 字段 | 可修改途径 |
|----|------|-----------|
| `user` | name, phone_number, qq_number, student_id, college, major | `PUT /user/profile`（本人） / `PUT /admin/users/:id`（admin） |
| `user` | login_email, role, state, email_type | 仅 `PUT /admin/users/:id`（admin） |
| `profile` | nickname, department, intro, email, blog_url, github_url | `PUT /user/profile`（本人，department 仅 software/media 有值可设） |
| `profile` | avatar | `PUT /user/avatar`（multipart/form-data，≤5MB，jpg/png/webp） |

#### 头像上传

- 上传至腾讯云 COS，返回 URL 写入 `profile.avatar`
- 后期接入 COS 内容审核（不良信息识别）

### 4.10 OAuth 2.1 授权服务

#### 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/oauth/authorize` | GET | 授权端点，**无认证**。强制参数：response_type=code / client_id / redirect_uri / scope / state / code_challenge / code_challenge_method；可选：nonce（OIDC） |
| `/oauth/authorize/consent` | POST | 授权确认端点，Bearer 认证。SAST Link 自有端点，使用标准信封 |
| `/oauth/token` | POST | Token 端点。支持 grant_type: authorization_code / refresh_token。第一方用 PKCE（无 client_secret），第三方用 client_secret_post。scope 含 openid 时额外返回 id_token |
| `/oauth/revoke` | POST | 撤销整条 token family |

#### 两段式授权流程

`GET /oauth/authorize` 不需要认证——从第三方跳转来的浏览器不会携带 `Authorization` header。流程拆为两段：

```
GET /oauth/authorize     → 校验参数 → Redis 暂存（ar_，10min）→ 302 至 OAUTH_CONSENT_URL
POST /oauth/authorize/consent  → Bearer 认证 → GetDel 消费暂存 → 建授权码 → 返回 redirect_uri
```

**决策依据**：采用两段式而非 cookie session，是为保持 §7.1「JWT 不存 cookie，不存在 CSRF 攻击面」；保留标准 `GET /oauth/authorize` 入口 URL，则是为让第三方 OAuth 库无需特殊适配。

授权码的 client / scope / PKCE challenge / nonce 全部取自暂存内容，不采信 consent 请求体的回传值——否则调用方可以确认一个请求而为另一个客户端或另一组 scope 签发授权码。暂存以 GetDel 原子消费，一个 `request_id` 最多产出一个授权码。

`family_id` 在用户点击同意的那一刻生成，由授权码传递给后续 token pair。这正是授权码重放能够撤销「已由该 code 签发的 token」的原因。

#### 安全约束

- Authorization Code 有效期 5min，单次使用（is_used 标记），过期后 pg_cron 每小时清理
- PKCE-S256 强制，仅接受 `code_challenge_method=S256`。V001 数据库历史约束仍允许 `plain` 存量值，实际协议层由 V002 迁移收紧为 S256-only。
- State 参数强制，回调时必须校验
- Redirect URI 必须**精确字符串相等**于 `oauth_clients.redirect_uris` 之一。不做前缀匹配：前缀规则允许攻击者追加客户端从未注册的路径并在那里接收授权码
- 第一方应用（`first_party`）：无 client_secret，PKCE 认证；可请求任意受支持的 scope，不受其注册 `scopes` 列的约束（该列对第一方客户端仅作记录用途）。因此新增 `first_party` 客户端等同于授予全量 scope，注册审批应按此对待
- 第三方应用（`third_party`）：client_secret_post 认证；scope 受注册时声明范围限制
- 公开客户端携带 `client_secret` 会被拒绝而非忽略——这说明客户端搞错了自己的类型
- 授权码重放检测：`is_used=TRUE` 的同 code 再次出现 → 通过 `family_id` 级联撤销整条 token 链
- **PKCE 校验失败同样消耗授权码**。否则窃得授权码的攻击者可对着一个始终有效的 code 无限枚举 `code_verifier`
- 授权码过期不触发级联撤销：过期的 code 从未被兑换，没有需要惩罚的 family
- `client_secret` 以 SHA-256 存储（非 PBKDF2）。client_secret 是 32 字节 crypto/rand 高熵值，不存在字典攻击面；而 PBKDF2 的 600k 迭代约 380ms/次，会让 token 端点成为 CPU 瓶颈。这与 API key 存 SHA-256 是同一论证
- `GET /oauth/authorize` 按调用方 IP 限流（默认 20 次/60s）：该端点无认证且每次调用写一个 Redis 暂存键
- **不支持 scope 收窄**（已知偏差）。RFC 6749 §6 允许 refresh 时请求更小的 scope，但仓储层要求轮换后的 token pair 携带与当前完全一致的 scope。客户端如需更小的 scope 须重新授权

#### 错误重定向规则

错误分两条路径，取决于 `redirect_uri` 是否已通过校验：

| 阶段 | 去向 | 携带 `state` |
|------|------|--------------|
| `client_id` / `redirect_uri` 校验通过之前 | `OAUTH_CONSENT_URL` | 否 |
| 校验通过之后 | 客户端 `redirect_uri` | 是 |

RFC 6749 §4.1.2.1 禁止把错误重定向到未经校验的 `redirect_uri`——否则任何人填入任意地址即可让本服务把浏览器弹送过去，端点退化为 open redirector。无法识别的错误按不可重定向处理：这恰恰是可重定向性无法确立的情形。

#### 响应格式

OAuth 端点不遵循 SAST Link 标准响应信封：

- `/oauth/authorize`：成功/错误均使用 redirect response。
- `/oauth/token`：请求体为 `application/x-www-form-urlencoded`；成功 `200` 返回 `{ "access_token", "refresh_token", "token_type", "expires_in", "scope", "id_token" }` 并携带 `Cache-Control: no-store` 与 `Pragma: no-cache`（RFC 6749 §5.1，防止共享缓存把一个客户端的 token 投递给另一个），错误使用 RFC 6749 JSON `{ "error": "invalid_grant", "error_description": "..." }`。`invalid_client` 为 `401` 并附带 `WWW-Authenticate`，其余错误为 `400`（RFC 6749 §5.2）。
- `/oauth/revoke`：请求体为 `application/x-www-form-urlencoded`；遵循 RFC 7009，成功固定 `200 OK` 空响应体，错误使用 OAuth JSON 格式。未知/已过期/已撤销的 token 一律 `200`——客户端诉求已成立，反之会把端点变成探测 token 存在性的 oracle。
- 请求参数只从请求体读取，query string 被忽略；重复参数直接拒绝（RFC 6749 §3.2，避免与链路上代理对生效值产生分歧）。

**例外**：`/oauth/authorize/consent` 是 SAST Link 自有端点而非 RFC 定义端点，沿用标准信封与业务错误码。

### 4.11 OIDC Provider

SAST Link 基于 OAuth 2.1 提供 OpenID Connect 1.0 兼容的身份认证层。

#### 端点

| 端点 | 说明 |
|------|------|
| `GET /.well-known/openid-configuration` | Discovery 文档，含 issuer、各端点 URL、支持的 scope/claim/alg |
| `GET /.well-known/jwks.json` | RS256 公钥集（JWKS），`kid` 与 JWT Header 匹配 |
| `GET /userinfo` / `POST /userinfo` | UserInfo 端点，Bearer Token 认证 |

#### ID Token

scope 含 `openid` 时，`POST /oauth/token` 响应额外返回 `id_token`：

```
Header: { "alg": "RS256", "kid": "link-v2-{year}-{month}", "typ": "JWT" }
Payload: {
  "iss": "https://link.sast.fun/v2",
  "sub": "1",                           // user.id 字符串
  "aud": "<client_id>",
  "exp": 1717400000, "iat": 1717396400,
  "auth_time": 1717396400,              // 用户授权确认时间
  "nonce": "n-0S6_WzA2Mj",             // 与授权请求 nonce 一致
  // profile scope:
  "name": "张三",
  "picture": "https://cos.example.com/avatar/1.jpg",
  "preferred_username": "张三",
  "profile": "https://link.sast.fun/card/1",
  "updated_at": 1717396400,
  // email scope:
  "email": "b2404****@njupt.edu.cn",
  "email_verified": true                // SAST Link 注册时已校验
}
```

#### Scope → Claims 映射

| Scope | ID Token / UserInfo Claims |
|-------|---------------------------|
| `openid`（必选） | `sub` |
| `profile` | `name`, `picture`, `preferred_username`, `profile`, `updated_at` |
| `email` | `email`, `email_verified` |

授权范围之外的 claim **完全不出现**，而非返回空值：relying party 无法区分 `"name": ""` 与「该用户没有名字」。ID Token 与 UserInfo 共用同一套 claim 构造与同一道 scope 闸门，因此两个端点对同一 token 不会给出不一致的结论。

- `preferred_username` 取 `profile.nickname`，未设置或为空白时回退到 `user.name`
- `profile` 指向公开名片 URL（`OAUTH_CARD_BASE_URL` + `/` + user ID）。该配置独立于 `JWT_ISSUER`：issuer 带 API 的 `/v2` 基路径，而名片是不带它的前端路由
- `auth_time` 取授权码行的 `created_at`——两段式流程中授权码正是在用户点「同意」那一刻创建的，语义精确，无需额外建列。refresh 轮换不是重新认证，因此保持该 family 首个 refresh token 的创建时刻
- ID Token 的 `aud` 是 `client_id`，与 access token（`aud` 为本服务）分属两条独立签名路径。若共用一条，要么破坏中间件的 audience 校验，要么签发出能被本服务当作自身 bearer 凭证接受的 ID Token

#### ID Token 与 Access Token 的关系

第三方 access token 仍使用服务 audience，因此能通过现有 JWT 中间件认证——`/userinfo` 正依赖这一点。`/userinfo` 自行完成认证而非挂在中间件之后，只是为了按 RFC 6750 格式应答（`WWW-Authenticate` 挑战头），token 校验逻辑本身复用中间件的 `Authenticate`。

### 4.12 管理后台

| 端点 | 方法 | 角色 | 说明 |
|------|------|------|------|
| `/admin/users` | GET | admin / lecturer | 分页列表，支持按 role / state / department / student_id / keyword 筛选 |
| `/admin/users/:id` | GET | admin / lecturer | 用户详情（含 profile + identities） |
| `/admin/users/:id` | PUT | admin | 更新用户信息（含 role / state / email_type） |
| `/admin/users/:id` | DELETE | admin | 软删除（state → is_deleted），级联撤销所有 token |
| `/admin/users/:id/restore` | PUT | admin | 恢复已注销用户（state: is_deleted → njupter） |
| `/admin/oauth-clients` | GET | admin | 客户端列表 |
| `/admin/oauth-clients` | POST | admin | 注册新客户端（第三方返回 client_secret，第一方不返回） |
| `/admin/oauth-clients/:id` | PUT | admin | 更新客户端（名称/回调地址/启用状态） |
| `/admin/audit-logs` | GET | admin | 分页查询，支持按 user_id / action / resource / success / 时间范围 筛选 |

#### 角色权限矩阵

| 操作 | freshman | member | lecturer | admin |
|------|----------|--------|----------|-------|
| 本人信息读写 | ✓ | ✓ | ✓ | ✓ |
| 绑定/解绑 | ✓ | ✓ | ✓ | ✓ |
| 查看用户列表/详情 | — | — | ✓ | ✓ |
| 编辑用户信息 | — | — | — | ✓ |
| 注销/恢复用户 | — | — | — | ✓ |
| 管理 OAuth 客户端 | — | — | — | ✓ |
| 查看审计日志 | — | — | — | ✓ |

**角色变更**：`PUT /admin/users/:id` 实际修改 `role` 时，必须在同一事务内递增 `user.token_version` 并撤销该用户的全部 token family。`role` 未变化或仅修改普通资料时，不递增 `token_version`。旧 Access Token 继续携带签发时的 `role`，但会因版本不匹配在认证阶段失效。另外角色鉴权本身读 DB `role`（见 §4.1「角色鉴权」），因此即使未递增 `token_version`，降权也在下一个请求立即生效。

**注销语义的唯一入口**：`PUT /admin/users/:id` 不接受 `state: is_deleted`，返回 `422`；对已注销用户调用亦然。注销只能走 `DELETE`、恢复只能走 `PUT .../restore` —— 只有这两条路径在同一事务内撤销全部 Token。若允许 PUT 直接置为 `is_deleted`，会留下「账号已注销但 Refresh Token 仍可换新 Access Token」的窗口（refresh 流程不比对 `token_version`）。`njupter` / `on_sast` / `retired_sast` 三者之间可任意修改，供管理员纠正误设。

**管理员自我保护**（契约未写明，实现补充，均返回 `403`）：

| 规则 | 理由 |
|------|------|
| 不可修改自己的 `role` | 自我降权不可自行恢复 —— 能撤销该操作的端点正是被交出的那一个 |
| 不可注销自己的账号 | 同上，注销后无法调用恢复端点 |
| 不可降权或注销最后一名活跃管理员 | 系统将无人可管理，只能直连数据库恢复 |

「活跃管理员」指 `role = 'admin' AND state <> 'is_deleted'`。最后一名管理员的判定是对其他行的 count，因此必须在写事务内完成：PostgreSQL 无法对聚合加 `FOR UPDATE`，两个并发降权请求会各自读到「还剩一名」并同时提交。所有相关写路径先取同一个 `pg_advisory_xact_lock` 再计数，使其串行化（与 §V005 跨表邮箱唯一性同一手法）。

**`email_type` 的一致性**：该字段只能与 `login_email` 一同提交且必须与其域名一致，否则 `400`。V001 触发器 `auto_set_email_type` 仅在 `login_email` 出现在 UPDATE 列中时才重算，单独提交 `email_type` 会写入与邮箱域名矛盾的值。

**客户端注册**：`client_id` 由服务端生成，不接受请求指定 —— 否则可注册为内置 first-party 客户端的 ID 并绕过 §7.1 的 `azp` 隔离。`redirect_uris` 在注册阶段即校验（仅 https，http 限 loopback；禁 fragment/userinfo/相对路径/首尾空白），这是开放重定向的第一道闸门：`/oauth/authorize` 做字节精确匹配，但精确匹配无法保护一个本身就危险的注册值。

**客户端停用**：`is_active` 由 `true` 改为 `false` 时，在同一事务内撤销该客户端全部 Access / Refresh Token。停用是安全动作，语义为「立即断开」而非「一小时后随 Access Token 自然过期」。`client_type`、`scopes`、`grant_types` 注册后不可修改。

### 4.13 审计日志

所有认证相关操作写入 `audit_logs`：

| 操作类型 | 触发场景 |
|----------|----------|
| `register` | 用户注册成功 |
| `login` | 密码登录 / OAuth 登录成功/失败 |
| `logout` | 用户登出 |
| `change_password` | 修改密码 |
| `reset_password` | 重置密码 |
| `oauth_bind` / `oauth_unbind` | 第三方账号绑定/解绑 |
| `update_profile` | 修改个人资料 |
| `upload_avatar` | 上传头像 |
| `admin_action` | admin 编辑/注销/恢复用户、管理 OAuth 客户端 |

日志字段：`user_id`、`action`、`resource`、`resource_id`、`detail`(JSONB)、`client_ip`(INET)、`user_agent`、`success`、`err_code`。用户删除后 `user_id` SET NULL 保留日志。

**detail JSONB 结构**（按 action 类型）：

| action | detail 内容 |
|--------|-----------|
| `register` | `{"login_email": "xxx@njupt.edu.cn"}` |
| `login` | `{"method": "password" \| "github" \| "lark" \| "other_mail"}` |
| `logout` | `{}` |
| `change_password` | `{}` |
| `reset_password` | `{}` |
| `oauth_bind` | `{"provider": "github" \| "lark" \| "other_mail", "provider_id": "xxx"}` |
| `oauth_unbind` | `{"provider": "github" \| "lark" \| "other_mail", "provider_id": "xxx"}` |
| `update_profile` | `{"changed_fields": ["name", "phone_number", ...]}` |
| `upload_avatar` | `{"avatar_url": "https://..."}` |
| `admin_action` | `{"target_user_id": 123, "sub_action": "edit_user" \| "delete_user" \| "restore_user" \| "manage_oauth_client"}` |

**数据保留**：audit_logs 保留 90 天，pg_cron 每天凌晨 4:00 清理过期数据。

### 4.14 个人卡片

- URL 格式：`https://link.sast.fun/card/{user.id}`（OIDC `profile` claim 也指向此 URL）
- 展示内容：nickname、department、intro、avatar、blog_url、github_url
- 用途：homepage 友链、个人名片分享

---

## 5. 数据模型

详见 `docs\psql-db-design.md`。核心表：

| 表 | 用途 | 关键设计 |
|----|------|----------|
| `user` | 用户主表 | `token_version` 支持全局 Token 失效；`state` 状态机驱动 |
| `profile` | 用户展示资料 | 1:1 关联 user，department 用于权限隔离 |
| `identities` | 第三方账号绑定 | provider + provider_id 全局唯一；github/lark 每用户仅 1 条（partial unique index）；other_mail 最多 2 条（触发器 + 应用层双重校验） |
| `oauth_clients` | OAuth 客户端注册 | first_party 的 client_secret 为 NULL；redirect_uris/grant_types/scopes 数组存储 |
| `oauth_authorizations` | 授权码 | PKCE 参数（code_challenge + method）+ OIDC nonce；`family_id` 支持重放检测级联撤销；无 updated_at |
| `oauth_access_tokens` | JWT 元数据 | `token_id` = JWT jti；`family_id` 级联撤销；无 updated_at |
| `oauth_refresh_tokens` | Refresh Token | `token_hash` = HMAC-SHA256 存储；`(family_id, sequence)` 唯一约束实现 rotation 检测；无 updated_at |
| `audit_logs` | 操作日志 | user_id ON DELETE SET NULL；JSONB detail |

### 用户状态机

```
njupter ──(加入SAST)──► on_sast
on_sast ──(离开SAST)──► retired_sast
njupter/on_sast/retired_sast ──(注销)──► is_deleted
is_deleted ──(恢复)──► njupter
```

---

## 6. Redis 场景

| 场景 | Key | TTL | 数据结构 | 说明 |
|------|-----|-----|----------|------|
| 验证码 | `sastlink:verify:{purpose}:{email}` | 5min | String（Lua 原子比对，匹配后 DEL） | `purpose` ∈ `register` / `reset_password` / `bind_email`。按用途分键，使某一流程签发的验证码无法用于另一流程。填错不删除验证码（否则任何人都能用一次错误提交作废他人验证码），改为累计失败次数 |
| 验证码失败计数 | `sastlink:verify:attempt:{purpose}:{email}` | 跟随验证码剩余 TTL | String（INCR） | 每个验证码最多 5 次尝试，用尽即连同验证码一并删除，避免 6 位码被无限爆破。重新发码时清零 |
| 限流 | `sastlink:ratelimit:{ip}:{endpoint}` | 30s~15min | String（INCR 计数器 + EXPIRE） | 固定窗口计数器，按端点差异化配置（登录 15min/发验证码 60s 等） |
| 设备管理 | `sastlink:devices:{user_id}` | 30d | Sorted Set（score=login_ts, member=device_id） | 最多 5 台同时登录，详情另存 Hash。淘汰/登出见 §6.1 |
| 解绑限流 | `sastlink:ratelimit:user:{user_id}:unbind` | 60s | Fixed window（INCR + EXPIRE） | 限制单个用户的解绑频率。键按 `user_id` 而非 `provider_id`：后者会让 A 解绑某地址后，B 绑定同一地址再解绑时撞上 A 的窗口。在密码校验**之前**检查，否则爆破尝试不消耗配额。此处用限流而非复用登录失败计数：后者的键与密码登录共用，在本端点试错密码会连带锁死用户的登录入口，且其响应为「登录已被锁定」，在解绑上语义不符；若要改为累积锁定，需要独立的键命名空间与错误码。并发解绑同一条记录由 PostgreSQL 串行化：输的一方匹配不到行，返回 `40400` |
| Token 黑名单 | `sastlink:token:blacklist:{jti}` | Token 剩余有效期 | String（SET EX，值任意） | 登出/改密后 Access Token 失效，利用 TTL 自动过期清理 |
| 幂等性 | `sastlink:idempotency:{key}` | 24h | String（SET NX，存响应体） | 敏感写操作（注册、绑定等）。key 由客户端传入（`Idempotency-Key` header），同一 key 重复请求返回首次结果 |
| OAuth State | `sastlink:oauth:state:{state}` | 10min | String（GetDel 消费） | OAuth 授权标准 state 参数，发起时写入，回调时 GetDel 校验防 CSRF |
| OAuth 注册暂存 | `sastlink:oauth:registration:{state}` | 15min | String（GetDel 消费，JSON 值） | OAuth 回调无绑定分支。暂存 `{provider, provider_id, identity_data, oauth_state}`，消费时校验双值匹配 |
| 登录码 | `sastlink:auth:login_code:{code}` | 60s | String（GetDel 消费） | OAuth 回调已有绑定用户分支，暂存 user_id，前端交换 Token Pair |
| 登录失败 | `sastlink:auth:login_failure:{email}` | 15min | String（INCR 计数器） | 连续失败 ≥ 10 次锁定，成功登录后 DEL 清零 |
| Register-Ticket | `sastlink:auth:register_ticket:{ticket}` | 5min | String（GET 校验 → 建号成功后 DEL） | 注册两步间暂存已验证邮箱。并发由 `login_email` UNIQUE 约束串行化，ticket 不承担选主职责，故保留到建号成功，竞态失败者可重试 |
| Bind-Ticket | `sastlink:auth:bind_ticket:{ticket}` | 5min | String（GET 校验 → 验证码通过后 DEL） | 绑定邮箱两步间暂存待绑定邮箱 + user_id。不在校验前消费，否则验证码填错会连 ticket 一起作废 |
| 授权请求暂存 | `sastlink:oauth:authorize_request:{request_id}` | 10min | String（SET NX 写入，GetDel 消费，JSON 值） | 两段式授权流程（§4.10）在 `GET /oauth/authorize` 与 `POST /oauth/authorize/consent` 之间暂存已校验的请求参数：`{client_id, redirect_uri, scopes, state, code_challenge, code_challenge_method, nonce}`。GetDel 保证一个 `request_id` 最多产出一个授权码；写入用 SET NX 而非覆盖，使一个 ID 只能绑定一组授权参数 |

### 6.0 Redis 不可用时的降级策略

每个 Redis 读写点必须明确声明故障行为，只有两类：

| 类别 | 判据 | 场景 | 故障行为 |
|------|------|------|----------|
| **Fail-closed** | Redis 是唯一存储，取不到值不等于校验通过 | 验证码、OAuth State、registration_state、login_code、Register-Ticket、Bind-Ticket、幂等性 key、授权请求暂存 | 拒绝请求，用户重走流程。所有 key 均带 TTL，冷启动自愈 |
| **Fail-open** | PostgreSQL 持有权威副本，或丢失仅放宽速率窗口 | Token 黑名单、登录失败计数与锁定、限流（含解绑限流、authorize 限流） | WARN 日志后继续，不返回 5xx |

Token 黑名单可以跳过的依据：JTI 写入黑名单与 `oauth_access_tokens.revoked_at` 在**同一事务**内完成，而登录态校验始终执行那条 DB 查询（§4.1），因此 DB 拒绝的集合是黑名单的严格超集。黑名单是快速拒绝路径与纵深防御，不是权威。

**禁止**把 fail-open 依赖的错误转成 `ErrInternal`——那会让一个可选缓存变成认证链路的单点故障。

### 6.1 设备管理

数据结构：Sorted Set + Hash 组合。

```
sastlink:devices:{user_id}    Sorted Set    score=login_timestamp  member=device_id
sastlink:device:{device_id}   Hash          {ua, ip, login_time, last_seen}
```

- **登录**：生成 `device_id`（UUID v4）→ `ZADD devices:{uid} {ts} {device_id}` → `HSET device:{device_id} ...`。两个 key TTL 均为 30d
- **淘汰**：`ZCARD` > 5 → `ZREMRANGEBYRANK 0 0`（移除最旧 1 条），对应 device Hash 同步删除
- **登出**：仅删除当前 `device_id`（`ZREM` + `DEL`），不影响其他设备
- **刷新 Token**：更新对应 device Hash 的 `last_seen` 字段，不续期 TTL

---

## 7. 安全设计

### 7.1 防攻击措施

| 威胁 | 措施 |
|------|------|
| 暴力破解 | 15min 内 10 次失败锁定；限流中间件按 IP 限制频率 |
| CSRF | OAuth state 参数强制；JWT 不存 cookie，不存在 CSRF 攻击面。授权确认走两段式 + Bearer 认证（§4.10）而非 cookie session，正是为了维持这一前提 |
| Open redirect | `/oauth/authorize` 的错误只在 `client_id` 与 `redirect_uri` 均校验通过后才允许重定向到客户端；`redirect_uri` 精确字符串匹配注册值（§4.10） |
| Token 泄露 | refresh_token rotation + 重放检测 + 全链撤销；token_version 改密全局失效 |
| 第三方 Token 越权访问内部接口 | Access Token 携带 `azp`（签发对象 client_id）；内部 API 中间件只接受 `azp` 等于内置 first-party 客户端的 token，第三方 token 一律 403。见下方「第三方 Token 隔离」 |
| 账号接管 | OAuth 绑定需登录态；registration_state 仅用于新建用户 + OAuth state 双重绑定，registration_state 泄露者无法单独滥用 |
| SQL 注入 | GORM 参数化查询 |
| 重放攻击 | 授权码/Register-Ticket/Bind-Ticket/login_code 均为一次性使用；幂等性 key 防敏感写操作重放 |

**第三方 Token 隔离**：内部会话 Token 与第三方 OAuth Access Token 共用同一个 `aud`（本服务），因为两种场景下内部 API 都是 resource server，`aud` 因此无法区分二者。若不加区分，一个仅获得 `openid` scope 的第三方 token 就能通过内部认证中间件拿到完整 principal，进而调用 `PUT /user/profile` 改资料、或走 `POST /user/identities/email` 绑定攻击者邮箱为登录方式——即账号接管。

因此 Access Token 增加 `azp` claim 记录签发对象，内部中间件（`middleware.Authenticate`）只接受 `azp` 等于 `INTERNAL_OAUTH_CLIENT_ID` 的 token，其余返回 403。`azp` 缺失视为内部会话 token（该 claim 引入前签发的 token 仅发给内置客户端）。

`/userinfo` 是唯一例外：它的存在意义就是服务第三方 token，因此走 `middleware.AuthenticateAnyClient`，不施加此限制，claims 仍按 token 自身 scope 过滤。该方法命名上即标注了适用范围，内部端点不得使用。

`INTERNAL_OAUTH_CLIENT_ID` 未配置时中间件拒绝所有请求而非放行所有客户端：配置缺失应当显式失败，而不是静默关闭这道检查。

### 7.2 安全响应头

| Header | 值 |
|--------|-----|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | `default-src 'self'` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |

CORS 通过 `CORS_ALLOWED_ORIGINS` 环境变量配置白名单。

### 7.3 密码策略

- 最短 8 位（NIST SP 800-63B）
- 不做强制复杂度（大小写/数字/特殊字符），前端引导用户设置强密码
- 新密码不能与旧密码相同（42202）

---

## 8. 可观测性

| 维度 | 方案 |
|------|------|
| 日志 | JSON 结构化日志（slog），含 trace_id / user_id / client_ip / method / path / status / latency |
| 健康检查 | `GET /health` → `{ "status": "ok", "db": "ok", "redis": "ok" }`；Redis 故障时返回 200 且 `redis` 为 `degraded`（见 §6.0），仅 `db` 故障返回 500 |
| 审计追踪 | `audit_logs` 表记录所有认证操作 |
| 错误码 | 统一 5 位业务码（`{HTTP状态}{序号}`），详见附录 A |

---

## 9. 数据运维

### 9.1 pg_cron 定时清理

| 任务 | 频率 | 清理对象 |
|------|------|----------|
| `cleanup-expired-authorizations` | 每小时 | `oauth_authorizations` 已过期 +1h 缓冲（无论是否使用） |
| `cleanup-expired-access-tokens` | 每小时 | `oauth_access_tokens` 已过期 +1h 缓冲 |
| `cleanup-revoked-refresh-tokens` | 每天 03:00 | `oauth_refresh_tokens` 已撤销 且 已过期 +1d 缓冲。注：+1d 仅为审计保留缓冲，不影响 refresh 逻辑——refresh_token 过期即不可用，不依赖清理任务 |
| `cleanup-expired-audit-logs` | 每天 04:00 | `audit_logs` 超过 90 天保留期的数据 |

### 9.2 备份策略

- PostgreSQL：每日全量备份（pg_dump），保留 30 天
- Redis：无需备份——所有 Key 均含 TTL，最长 24h（幂等性），丢失后自动冷启动，不影响数据正确性

---

## 10. API 设计

### 10.1 响应规范

- **标准端点**：统一响应信封 `{ "code": 0, "message": "ok", "data": {...} }`
- **OAuth 端点**：`/oauth/authorize` 成功/错误均使用 redirect response；`/oauth/token` 成功和错误均使用 RFC 6749 JSON 格式（成功另带 `Cache-Control: no-store`）；`/oauth/revoke` 使用 RFC 7009，成功固定 `200 OK` 空响应体，错误使用 OAuth JSON 格式。**例外**：`/oauth/authorize/consent` 是自有端点而非 RFC 定义端点，使用标准信封。
- **OIDC UserInfo 端点**：错误时 RFC 6750 格式 `{ "error": "invalid_token", "error_description": "..." }`，并附带 `WWW-Authenticate` Bearer 挑战头
- **OIDC Discovery / JWKS**：直接返回协议标准 JSON（`/.well-known/openid-configuration`、`/.well-known/jwks.json`）
- **健康检查**：直接返回 `{ "status", "db", "redis" }`
- **个人卡片公开端点**：`/card/{id}` 直接返回公开 profile 字段

### 10.2 Base URL

`https://link.sast.fun/v2`

### 10.3 认证方式

`Authorization: Bearer <access_token>`（JWT RS256，1h 有效期）

### 10.4 完整端点列表

详见 [API 文档](API文档.md) 及 [OpenAPI 规范](openapi.yaml)。

---

## 附录 A：业务码速查

| 码段 | 类别 | 示例 |
|------|------|------|
| `0` | 成功 | — |
| `400xx` | 参数错误 | 40000 参数错误 / 40010 验证码错误 / 40020 邮箱域名不允许 |
| `401xx` | 认证错误 | 40100 未登录 / 40105 密码错误 / 40106 邮箱不存在 |
| `403xx` | 权限错误 | 40300 无权限 / 40301 账号已注销 / 40302 非 SAST 企业飞书用户 |
| `404xx` | 资源不存在 | 40401 用户不存在 / 40402 OAuth 客户端不存在 |
| `409xx` | 资源冲突 | 40901 邮箱已注册 / 40903 第三方账号已绑定 / 40905 第三方邮箱绑定上限 |
| `422xx` | 业务校验失败 | 42201 密码长度不足 / 42202 新旧密码相同 |
| `429xx` | 频率限制 | 42900 请求过于频繁 |
| `500xx` | 服务端错误 | 50000 内部错误 / 50001 邮件发送失败 / 50002 对象存储上传失败 / 50003 数据库错误 |

## 附录 B：枚举值速查

| 枚举 | 值 |
|------|-----|
| `user_role` | `freshman` / `member` / `lecturer` / `admin` |
| `state` | `njupter` / `on_sast` / `retired_sast` / `is_deleted` |
| `department` | `software` / `media` |
| `email_type` | `njupt_email` / `sast_email` |
| `login_method` | `github` / `lark` / `other_mail` |
| `client_type` | `first_party` / `third_party` |
| `college` | 贝尔英才学院 / 通信与信息工程学院 / 电光柔学院 / 集成电路科学与工程学院（产教融合学院）/ 计算机学院、软件学院、网络空间安全学院 / 自动化学院 / 人工智能学院 / 材料科学与工程学院 / 化学与生命科学学院 / 物联网学院 / 理学院 / 现代邮政学院、智慧交通学院 / 数字媒体与设计艺术学院 / 管理学院 / 经济学院 / 社会与人口学院、社会工作学院 / 外国语学院 / 教育科学与技术学院 / 波特兰学院 / 其他 |

## 附录 C：实现状态追踪

| 模块 | 状态 |
|------|------|
| Go 服务骨架 | 已完成 — 配置、PostgreSQL/Redis 连接、Gin router、结构化日志与健康检查 |
| 数据基础层 | 已完成 — V001–V005 SQL migrations、固定内置 `sast-link-web` first-party Client、token blacklist Outbox、baseline guard、persistence entities、Auth repositories 与 PostgreSQL 16 integration tests |
| 认证基础设施 | 已完成 — PBKDF2-SHA512、RS256 JWT/JWKS 与密钥轮换、opaque Refresh Token、PKCE-S256、统一 `openid/profile/email` scope、token-family rotation/replay、Redis 一次性状态/JTI 黑名单/登录失败计数与 fixed-window limiter |
| 内部会话业务 | 已完成 — 密码登录、Refresh Token rotation、登出、JWT middleware、当前用户资料查询、登录限流与登录/登出审计接入 |
| 用户注册与密码管理 | 已完成 — 邮箱验证码注册、改密 / 重置密码、全量 Token 吊销、第三方邮箱绑定 |
| 用户资料管理 | 部分完成 — 资料编辑（`PUT /user/profile`）、绑定列表、解绑（密码二次确认 + 唯一登录方式保护 + 60s 限流）、公开个人卡片（`GET /card/:id`）已完成；头像上传待实现（依赖对象存储接入） |
| OAuth/OIDC 业务 | 已完成 — 授权服务端（两段式 authorize / consent / token / revoke，PKCE-S256、授权码与 refresh 重放级联撤销）、OIDC Provider（discovery / JWKS / UserInfo / ID Token）、OAuth 客户端管理 endpoints（`GET`/`POST /admin/oauth-clients`、`PUT /admin/oauth-clients/:id`，服务端生成 `client_id`、注册期 redirect_uri 校验、内置客户端保护），以及第三方登录（GitHub / 飞书授权跳转与回调、`login_code` 交换、登录态绑定 `POST /user/identities/{github,lark}`、registration_state + oauth_state 双重校验的注册补全）。飞书以 `union_id` 作 `provider_id` 并校验 `tenant_key` 限 SAST 租户；回调重定向按精确匹配白名单校验；`oauth_state` / `registration_state` / `login_code` 三者均为 GetDel 一次性消费且 fail-closed。含跨层端到端集成测试（真实 PostgreSQL + Redis） |
| 管理后台 | 已完成 — OAuth 客户端管理、用户管理（分页列表 / 详情 / 更新 / 软删 / 恢复）与审计日志查询，读写分级鉴权（`GET /admin/users` 与详情开放 lecturer，其余 admin only），含跨层端到端集成测试（真实 PostgreSQL + Redis）。管理员自我保护：不可改自己的 role、不可注销自己、不可降权或注销最后一名活跃管理员（DB 事务内 advisory lock 串行化计数） |
| 其余运维接入 | 待实现 — 设备管理、其他 endpoint 限流策略与 pg_cron |

## 11. 实现顺序

- [x] Go 服务骨架（配置 / DB 与 Redis 连接 / Web 基础设施 / 健康检查）
- [x] 数据基础层（V001–V005 migrations / 内置 first-party Client / token blacklist Outbox / baseline / entities / repositories / integration tests）
- [x] 认证基础设施（PBKDF2 / JWT + JWKS / Refresh Token / PKCE-S256 / scope / Redis auth state + limiter / token-family rotation）
- [x] 内部会话闭环（密码登录 / JWT middleware / Refresh rotation / 登出 / 当前用户资料 / 登录限流与审计）
- [x] 用户注册与密码管理（验证码 / 注册 / 改密 / 重置密码 / 第三方邮箱绑定）
- [x] 用户资料自助管理（资料编辑 / 绑定列表 / 解绑 / 公开个人卡片）
- [ ] 头像上传（依赖对象存储接入，与内容审核一并实现）
- [x] OAuth 登录（GitHub / 飞书 回调 + login_code 交换）
- [x] OAuth 绑定 / 解绑 + 注册补全（registration_state + oauth_state 双重校验流程）
- [ ] 限流与防刷扩展（登录 endpoint 已接入；验证码、注册等策略待对应业务实现）
- [ ] 审计日志扩展（登录/登出已接入；其余业务随 endpoint 实现）
- [ ] 头像内容审核（腾讯云 COS）
- [x] OAuth 2.1 授权服务端（两段式 authorize / consent / token / revoke + PKCE-S256 + 重放级联撤销）
- [x] OIDC Provider（discovery / JWKS / UserInfo / ID Token）
- [x] OAuth 客户端注册 API（`/admin/oauth-clients` 列表 / 注册 / 更新，打通第三方客户端创建入口与 `client_secret` 校验路径）
- [x] 管理后台用户管理与审计日志查询（用户列表 / 详情 / 更新 / 软删 / 恢复 / 审计日志）
- [ ] pg_cron 定时清理
- [x] 个人卡片端点（`GET /card/:id`；前端页面另计）
- [ ] 测试、联调、上线
