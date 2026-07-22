# SAST Link Backend V2

SAST Link 是南京邮电大学校大学生科学技术协会（SAST）的统一身份认证中心与人员信息管理系统。

当前仓库已完成 Go 服务骨架、数据基础层与认证基础设施：HTTP API 入口、PostgreSQL/Redis 连接、健康检查、V001/V002 SQL migrations、持久化实体与 Auth repositories，以及密码哈希、RS256 JWT/JWKS、opaque Refresh Token、PKCE-S256、统一 OAuth/OIDC scope、Redis 一次性状态与 fixed-window limiter。完整测试覆盖 PostgreSQL 16 和 Redis Testcontainers。认证业务流程、OAuth/OIDC endpoints、限流中间件与 pg_cron 运维任务仍待接入。

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
- `internal/auth/`：密码哈希、JWT/JWKS、opaque Refresh Token、PKCE-S256 与统一 scope primitives
- `internal/redis/`：一次性认证状态、JTI blacklist、token version cache 与 fixed-window limiter
- `internal/model/`：GORM persistence entities 与 PostgreSQL 类型
- `internal/repository/`：user/token/audit repositories 与 token-family rotation/revocation
- `internal/migration/`：migration runner 与 V001 baseline guard
- `internal/testutil/`：PostgreSQL 16 Testcontainers 测试基础设施

## License

[MIT](./LICENSE) © NJUPT SAST
