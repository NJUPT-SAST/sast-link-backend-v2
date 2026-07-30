# SAST Link Backend V2

SAST Link 是南京邮电大学校大学生科学技术协会（SAST）的统一身份认证中心与人员信息管理系统。

当前仓库已完成 Go 服务骨架、数据基础层、认证基础设施、内部认证闭环、用户资料自助管理、OAuth 2.1/OIDC Provider 与管理后台（OAuth 客户端 + 用户管理 + 审计日志）：HTTP API 入口、PostgreSQL/Redis 连接、健康检查、V001–V005 SQL migrations（含固定内置 `sast-link-web` first-party Client、token blacklist Outbox 与跨表邮箱唯一性触发器）、持久化实体与 Auth repositories、密码哈希、RS256 JWT/JWKS、opaque Refresh Token、PKCE-S256、统一 OAuth/OIDC scope、Redis 一次性状态/限流/登录失败计数，以及密码登录、Token 刷新、登出、JWT middleware、可靠黑名单投递 worker、SMTP 邮件、两步邮箱注册、改密/重置密码（含全量 Token 吊销与授权码作废）、第三方邮箱绑定、资料查询与编辑、绑定列表、解绑（密码二次确认 + 唯一登录方式保护 + 按用户限流）和公开个人卡片。

OAuth/OIDC Provider 部分已完成两段式授权端点（`GET /oauth/authorize` + `POST /oauth/authorize/consent`）、Token 端点（authorization_code 与 refresh_token 两种 grant、ID Token 签发）、RFC 7009 撤销端点、`/userinfo`、OIDC discovery 与 JWKS，以及 `/admin/oauth-clients` 客户端注册与更新（内置客户端受保护，不可停用或改写 redirect_uris）。

管理后台已完成用户管理（`/admin/users` 分页列表与详情、更新、软删注销、恢复）与审计日志查询（`/admin/audit-logs`）。鉴权按读写分级：列表与详情开放 lecturer，其余仅 admin。注销与角色变更在同一事务内递增 `token_version` 并撤销该用户全部 Token；管理员不可修改自己的角色、不可注销自己，也不可降权或注销系统中最后一名活跃管理员。

头像上传、第三方 OAuth 登录、设备管理与 pg_cron 运维任务仍待接入。

`cmd/api` 只负责运行 HTTP 服务，启动时不会执行 DDL 或 schema migration。数据库结构只能通过 `cmd/migrate` 显式管理。

## Documents

- [产品需求文档](./docs/SAST%20Link%20v2%20PRD.md)
- [数据库设计](./docs/psql-db-design.md)
- [OpenAPI 规范](./docs/openapi.yaml)
- [API 文档](./docs/API文档.md)

## Development

完整 integration tests 会通过 Testcontainers 启动 disposable PostgreSQL 16，需要本机 Docker：

```powershell
go test -race -shuffle=on -coverprofile=coverage.out -covermode=atomic ./...
go build -o bin/api.exe ./cmd/api
go build -o bin/migrate.exe ./cmd/migrate
golangci-lint run ./...
```

## Database migrations

```powershell
.\bin\migrate.exe version
.\bin\migrate.exe up
```

现有生产数据库已具备 V001 schema，不能运行 V001 `up`。接管 migration version 前必须遵循 [V001 baseline runbook](./docs/runbooks/database-baseline.md)。完成 runbook 的 preflight 后，使用：

```powershell
.\bin\migrate.exe force 1 --confirm-existing-baseline
```

后续生产 migration 必须显式确认：

```powershell
.\bin\migrate.exe up --confirm-production
```

主要目录：

- `cmd/api/`：HTTP API 的 Composition Root，按入口、依赖装配和 server 生命周期拆分，不执行 migration
- `cmd/migrate/`：唯一 migration runner
- `migrations/`：embedded versioned SQL migrations
- `internal/auth/`：密码哈希、JWT/JWKS、opaque Refresh Token、PKCE-S256
- `internal/scope/`：OAuth/OIDC scope 常量、归一化与校验
- `internal/errcode/`：跨层共享的业务错误码常量
- `internal/config/`：环境变量配置加载与校验
- `internal/db/`：GORM PostgreSQL 连接管理
- `internal/health/`：健康检查 handler
- `internal/service/session/`：内部登录、Refresh rotation、登出撤销与资料查询用例
- `internal/service/session/worker/`：token blacklist Outbox 的 Redis 投递与重试 worker
- `internal/adapter/redis/session/`：将 Redis 限流、登录失败计数和 JTI blacklist 适配到 Session ports
- `internal/web/`：Gin router、JWT middleware、认证 handlers 与基础响应设施
- `internal/redis/`：一次性认证状态、JTI blacklist、登录失败计数与 fixed-window limiter
- `internal/model/`：GORM persistence entities 与 PostgreSQL 类型
- `internal/repository/`：user/token/audit repositories 与 token-family rotation/revocation
- `internal/migration/`：migration runner 与 V001 baseline guard
- `internal/testutil/`：PostgreSQL 16 与 Redis 8 Testcontainers 测试基础设施

## License

[MIT](./LICENSE) © NJUPT SAST
