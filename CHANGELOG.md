# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

本仓库尚未发布版本，全部条目暂记在 `[Unreleased]` 下。每条标注日期与 PR（#N），可据此追到对应 commit。标注「perf 分支」的条目来自分支 `perf/optimization`，尚未合入 `main`；其余条目均已合入 `main`。

## [Unreleased]

### Added

- **工程基础设施**（2026-06-09 ~ 06-11）：仓库初始快照、PRD / API / OpenAPI / DB 设计文档交叉校验、CI 流水线、pre-commit、CONTRIBUTING、lint 配置、CI 最小权限。
- **HTTP 骨架**（2026-07-05，[PR #18](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/18)）：Go module、环境配置加载器、golangci-lint v2、响应信封 `{code, message, data}`、请求日志、Gin router、PostgreSQL / Redis 连接包、`GET /health`、API entrypoint。
- **数据基础 V001**（2026-07-19，[PR #20](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/20)）：V001 schema migrations 与 baseline guard、`cmd/migrate`（唯一 migration runner）、GORM 实体、Auth repository、Testcontainers（PostgreSQL 16）集成测试。
- **认证基础设施**（2026-07-22，[PR #22](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/22)）：PBKDF2 密码哈希、RS256 JWT/JWKS（active/previous kid 轮换）、opaque refresh token（HMAC-SHA256 存储）、PKCE-S256 原语、V002 强制 S256-only PKCE、OAuth scope 集中（`internal/scope`）、Redis 一次性状态 / JTI 黑名单 / 登录失败计数 / fixed-window 限流器。
- **内部会话闭环**（2026-07-26，[PR #23](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/23)）：密码登录、refresh rotation / replay 处理、登出、JWT middleware、`GET /user/profile`；V003 内置 first-party `sast-link-web` client seed、V004 token blacklist outbox（撤销事务写 outbox，worker 批量投递）；登录失败计数用 Lua 原子 INCR+PEXPIRE。
- **Redis 降级策略**（2026-07-26，[PR #25](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/25)）：health 把可选 Redis 报 `degraded` 而非 error；JTI 黑名单不可用时 middleware 回落 DB `revoked_at`；登录守卫与发码限流按策略 fail-open。
- **注册 / 密码 / 邮箱绑定**（2026-07-28，[PR #26](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/26)）：两步邮箱注册（Register-Ticket 一次性消费，`college` 必填 + 枚举校验）、忘记 / 重置密码（统一成功响应）、修改密码（`token_version` bump + 全量撤销，同事务）、第三方邮箱绑定（每用户 other_mail 上限 2）与解绑、V005 跨表邮箱唯一、SMTP mailer（收件人校验 + semaphore 限并发）。
- **资料自助服务**（2026-07-28，[PR #27](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/27)）：`PUT /user/profile`、`GET /card/:id`、`GET /user/identities`、`DELETE /user/identities/:id`（密码确认 + 唯一登录方式保护 + 按用户限流）。
- **OAuth 2.1 / OIDC Provider 与客户端管理**（2026-07-30，[PR #28](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/28)）：`GET /oauth/authorize` + `POST /oauth/authorize/consent` 两段式授权、token 端点（authorization_code + refresh_token，签发 ID Token）、RFC 7009 `POST /oauth/revoke`、`/userinfo`、discovery、JWKS；`/admin/oauth-clients` 客户端注册与更新（内置客户端受保护）；鉴权基础设施 `RequireRole`（从 DB 读角色）与 RFC 6750 `Authenticate` / `SetPrincipal`。
- **管理后台用户管理**（2026-07-31，[PR #29](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/29)）：`/admin/users` 分页列表 / 详情 / 更新 / 软删 / 恢复、`/admin/audit-logs` 审计日志查询；读写分级鉴权（列表与详情开放 lecturer，写操作仅 admin）；管理员自保护（不可改自己角色、不可注销自己）。
- **第三方 OAuth 登录**（2026-07-31，[PR #30](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/30)）：GitHub / 飞书授权跳转与回调、`login_code` 一次性交换（回调只投递 code）、登录态绑定、`registration_state` + `oauth_state` 双重校验的注册补全；飞书 `union_id` 作 `provider_id`、`tenant_key` 限 SAST 租户；compose 自包含本地栈；Caddy runbook。
- **端点限流**（2026-08-01，[PR #32](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/32)）：四个未限流端点补上限，`/auth/register/send-code` 按 Register-Ticket 配额而非调用方 IP；新增 `/auth/refresh` per-IP 限流。
- **数据保留 worker**（2026-08-01，[PR #33](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/33)）：过期授权码 / access / refresh 元数据 / 审计日志清理从 pg_cron 改为进程内 ticker worker，多实例用 PostgreSQL advisory lock 协调；V006 全量 `expires_at` 索引；retention 窗口可配置。
- **头像上传**（2026-08-03，[PR #34](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/34)）：`PUT /user/avatar`（≤5MB，jpg/png/webp 魔数 + 解码校验）、腾讯云 COS 存储、内容审核（fail-closed）、旧头像删除、按用户限流、审计 `upload_avatar`；`STORAGE_*` 配置；`internal/objectstore` ports + `internal/adapter/cos` 适配器。
- **设备管理**（2026-08-04，[PR #36](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/36)）：`GET /user/devices` + `DELETE /user/devices/:id`；设备记录存 Redis，`device_id` 复用 token `family_id`——设备生命周期与会话生命周期天然同步。密码 / 注册 / GitHub / Lark 登录均登记设备，任一会话终止路径（登出、登出指定设备、淘汰、改密、重置、刷新重放 / 轮换失败 / 过期、admin 降级 / 注销）同步清记录并审计（`logout_device` / `evict_device`）。5 台上限淘汰最旧设备并**真撤销其 family**（不沦为显示约束）；过期记录刷新时复活（受上限约束）；幻影成员（Hash 丢失）不占名额；设备记录 fail-open、`DeviceOwnedBy` 归属校验 fail-closed。Lua 原子原语（ZADD + HSET + 幻影清扫 + 淘汰）实现；review 修复：淘汰撤销延迟到轮换提交后（被判定死亡的刷新不误伤健康设备）、Hash 丢失重建时 `login_time` 从 ZSET score 还原。
- **压测工具**（perf 分支，2026-08-04）：`scripts/loadmix/`（client/mix/burst/refresh/pool/stats）与 all-in-one bench 镜像。

### Changed

- **JWT 从 RS256 换 EdDSA（Ed25519）**（perf 分支）：JWKS 变 `kty=OKP/crv=Ed25519/alg=EdDSA`、discovery `id_token_signing_alg_values_supported=["EdDSA"]`、ID Token 同算法；密钥解析改 PKCS8，部署需换 Ed25519 密钥；验签 leeway 缩到 5s。
- **auth-state 缓存取代 JTI 黑名单**（perf 分支）：中间件把 DB 权威的撤销 / 角色状态按 JTI 短 TTL 缓存（`AUTH_STATE_CACHE_TTL`，默认 15s），撤销路径写短 TTL tombstone（非 DEL）且缓存回填用 SET NX——关死撤销写竞态，撤销后旧角色无法通过竞态复活；缓存故障回落 DB（fail-open）。
- **refresh grace period（30s）**（perf 分支）：并发刷新不再撤销整个 token family，双 tab 刷新不登出；超窗口的真 replay 才切族。
- **新哈希统一 argon2id**（perf 分支）：默认 m=19456KiB / t=2（OWASP 低内存底线），存量 `pbkdf2-sha512-v1` 只读验证、登录成功后 rehash（`ShouldRehash`）；派生内存上界 64MiB；并发默认 `GOMAXPROCS`（1c1g=1）而非固定 64。取舍：login 因此是刻意保留的 CPU 热点，校园流量以读为主，读路径不受影响。
- **刷新轮换审计并入同一事务**（perf 分支）：`audit_logs` 直写，消除审计与轮换之间的窗口。
- **GORM `PrepareStmt` 与连接池**（perf 分支）：热查询缓存 PREPARE（MaxSize 128 / TTL 5m）；连接池 maxOpen 10 / maxIdle 3 / idle 5m / lifetime 30m。
- **运行时**（perf 分支）：`automaxprocs` 按容器 cgroup 配额校准 `GOMAXPROCS`、采集 `cmd/api/default.pgo` 跑 PGO、server 补 ReadTimeout 30s / WriteTimeout 10s / IdleTimeout 60s、`GOMEMLIMIT=900MiB`、gin 非 development 自动 release、pprof 改 fail-closed（仅 development 或 `PPROF_ENABLED=true`）。
- **Redis 参数**（perf 分支）：MaxRetries=0、MinIdleConns=4、拨号 / 读写短超时，Redis 挂时快速失败而不是挂住请求。
- **限流按校园 NAT 放宽**（perf 分支）：per-IP 总值提高但保留有意义的节流（login 5→300/15m、token/refresh/authorize/oauth-login/exchange-code →100/min、send-code IP 10→30/min 等），登录防御回到按账号锁定（`LOGIN_FAILURE_LIMIT`）。
- **blacklist worker**（perf 分支）：一次性 pipeline 失效一批 auth-state key，空队列按退避间隔休眠。
- **包布局按职责重构**（2026-07-26，[PR #24](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/24)）；LF 行尾统一。
- **OAuth 加固**（2026-07-30，[PR #28](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/28)）：`state` 逐字节返回、错误体不回显请求文本、token 认证失败不泄露客户端存在性 / 类型、discovery 不再宣称不支持的 `auth_time`、过期 access token 撤销其所属 family、`JWT_ISSUER` 规范化保证 `iss` 与 discovery 一致、loopback host 按 ASCII 折叠。
- **管理后台合同收紧**（2026-07-31，[PR #29](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/29)）：`page_size` 超上限直接 422 拒绝而非截断；管理端写的 `login_email` 拒绝不可见 codepoint。
- **资料编辑与解绑**（2026-07-28，[PR #27](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/27)）：profile 用 upsert 替代读后写；JSONB 修正为 JSON 序列化（之前会 base64）；解绑 cooldown 改为按用户限流。
- **容器以非特权用户运行**（2026-08-01，[PR #31](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/31)）。

### Removed

- **pg_cron 清理方案**（2026-08-01，[PR #33](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/33)）：被进程内 retention worker 取代；不用 pg_cron，因为生产库未安装该扩展且测试镜像无法加载。

### Fixed

- x/net 升级修 CVE-2026-25680、x/text 升级修 GO-2026-5970（2026-07-22 / 07-27）。
- 认证基础设施修复（2026-07-22，[PR #22](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/22)）：refresh rotation 原子化、限流器溢出、hash decode、空 JWT key ID 拒绝。
- 注册 / 密码 / 邮箱绑定修复（2026-07-28，[PR #26](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/26)）：跨表邮箱唯一（`login_email` 不能同时是 other_mail 身份）、注册冲突错误映射到具体字段、错误验证码 / 被拒请求不再烧一次性 token、mailer 收件人校验防 header 注入、验证码 key 按 purpose 隔离、错误信息中文化。
- 管理后台修复（2026-07-31，[PR #29](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/29)）：最后一名活跃管理员在事务内用 `pg_advisory_xact_lock` 判定，不再从写前读。
- refresh 失败审计补录（2026-08-01，[PR #32](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/32)），此前只记成功轮换。
- 头像上传加固（2026-08-03，[PR #34](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/34)）：COS HTTP client 加往返超时、被拒文件名记诊断日志、内容审核结果用专用错误码。

### Security

- 请求日志对 `code` / `state` / `code_challenge` / `registration_state` / `oauth_state` / `login_code` 脱敏（perf 分支）。
- 忘记密码统一成功响应，不暴露账号存在性（2026-07-28，[PR #26](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/26)）。
- 第三方回调重定向按精确匹配白名单校验（2026-07-31，[PR #30](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/30)）。
- provider endpoint URL 常量标 `#nosec G101`（2026-08-03，[PR #35](https://github.com/NJUPT-SAST/sast-link-backend-v2/pull/35)）。
