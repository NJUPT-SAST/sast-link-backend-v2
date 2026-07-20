# SAST Link Backend V2

SAST Link 是南京邮电大学校大学生科学技术协会（SAST）的统一身份认证中心与人员信息管理系统。

当前仓库已完成 Go 服务骨架与数据基础层：HTTP API 入口、PostgreSQL/Redis 连接、健康检查、V001 SQL migration、持久化实体、最小 Auth repositories 以及 PostgreSQL 16 integration tests。认证、OAuth/OIDC、限流和 pg_cron 运维任务仍待实现。

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
- `internal/model/`：GORM persistence entities 与 PostgreSQL 类型
- `internal/repository/`：最小 user/token/audit repositories
- `internal/migration/`：migration runner 与 V001 baseline guard
- `internal/testutil/`：PostgreSQL 16 Testcontainers 测试基础设施

## License

[MIT](./LICENSE) © NJUPT SAST
