# SAST Link Backend V2

SAST Link 是南京邮电大学校大学生科学技术协会（SAST）的统一身份认证中心与人员信息管理系统。

当前仓库已完成 Go 服务骨架、数据基础层、认证基础设施与首个内部认证闭环：HTTP API 入口、PostgreSQL/Redis 连接、健康检查、V001–V004 SQL migrations（含固定内置 `sast-link-web` first-party Client 与 token blacklist Outbox）、持久化实体与 Auth repositories、密码哈希、RS256 JWT/JWKS、opaque Refresh Token、PKCE-S256、统一 OAuth/OIDC scope、Redis 一次性状态/限流/登录失败计数，以及密码登录、Token 刷新、登出、JWT middleware、可靠黑名单投递 worker 和当前用户资料查询。注册/验证码/密码管理、资料编辑、OAuth/OIDC endpoints、设备管理与 pg_cron 运维任务仍待接入。

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

- `cmd/api/`：HTTP API 服务，不执行 migration
- `cmd/migrate/`：唯一 migration runner
- `migrations/`：embedded versioned SQL migrations
- `internal/auth/`：密码哈希、JWT/JWKS、opaque Refresh Token、PKCE-S256
- `internal/scope/`：OAuth/OIDC scope 常量、归一化与校验
- `internal/config/`：环境变量配置加载与校验
- `internal/db/`：GORM PostgreSQL 连接管理
- `internal/health/`：健康检查 handler
- `internal/service/session/`：内部登录、Refresh rotation、登出撤销与资料查询用例
- `internal/web/`：Gin router、JWT middleware、认证 handlers 与基础响应设施
- `internal/redis/`：一次性认证状态、JTI blacklist、token version cache、登录失败计数与 fixed-window limiter
- `internal/model/`：GORM persistence entities 与 PostgreSQL 类型
- `internal/repository/`：user/token/audit repositories 与 token-family rotation/revocation
- `internal/worker/`：token blacklist Outbox 的 Redis 投递与重试 worker
- `internal/migration/`：migration runner 与 V001 baseline guard
- `internal/testutil/`：PostgreSQL 16 与 Redis 8 Testcontainers 测试基础设施

## License

[MIT](./LICENSE) © NJUPT SAST
