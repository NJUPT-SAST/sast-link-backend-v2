# AGENTS.md

## Repository Status

SAST Link Backend V2 currently has a Go data foundation: the `cmd/api` HTTP service skeleton, `cmd/migrate` migration CLI, embedded V001 PostgreSQL schema migration, persistence entities, minimal repositories, and PostgreSQL 16 integration tests. Authentication, OAuth/OIDC, rate limiting, and pg_cron operations remain unimplemented.

`cmd/api` connects PostgreSQL and Redis and exposes the HTTP service; it must never perform DDL or schema migrations on startup. Only `cmd/migrate` may inspect or alter schema migration state.

## Commands

Full integration tests provision PostgreSQL 16 through Testcontainers and require Docker.

```powershell
# Run the complete suite
go test -race -shuffle=on ./...

# Run static analysis
golangci-lint run ./...

# Build executables
go build -o bin/api.exe ./cmd/api
go build -o bin/migrate.exe ./cmd/migrate

# Inspect and apply migrations
.\bin\migrate.exe version
.\bin\migrate.exe up
```

## Database Baseline

Production already contains the V001 schema. Follow `docs/runbooks/database-baseline.md` to register that pre-existing schema without DDL; do not run V001 `up` in production. After its required preflight checks, the guarded registration command is:

```powershell
.\bin\migrate.exe force 1 --confirm-existing-baseline
```

## Key Paths

- `cmd/api/`: HTTP API process; never runs DDL or migrations.
- `cmd/migrate/`: only schema migration runner.
- `migrations/`: embedded V001 initial schema migration.
- `internal/model/`: GORM persistence entities and database types.
- `internal/repository/`: minimal user, token, and audit-log repositories.
- `internal/migration/`: migration and guarded V001 baseline support.
- `internal/testutil/`: PostgreSQL 16 Testcontainers helper.
- `docs/runbooks/database-baseline.md`: production V001 baseline procedure.
- `docs/SAST Link v2 PRD.md`: product requirements and implementation tracking.

## CI And Security

The manually dispatched CI workflow lints the Go module, runs race-enabled tests against PostgreSQL 16 and Redis 8 service containers, and builds `cmd/api`. The weekly security workflow runs `gosec` and `govulncheck` against the current Go module.
