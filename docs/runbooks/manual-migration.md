# 手动数据库 Migration 操作手册

## 目的

本文档说明如何使用项目内置的 migration CLI，手动检查并应用 SAST Link Backend V2 的 PostgreSQL schema migrations。

注意：API 服务启动时不会执行 DDL，也不会自动迁移数据库。当前项目中只有 `cmd/migrate` 允许检查或变更 migration 状态。

本文适用于 V002 及后续普通 migration。若生产库已经存在 V001 schema，但尚未登记 migration metadata，请先遵循 `docs/runbooks/database-baseline.md`，不要在该生产库上执行 V001 `up`。

## 支持的命令

migration CLI 当前只支持以下命令：

```powershell
.\bin\migrate.exe version
.\bin\migrate.exe up
.\bin\migrate.exe up --confirm-production
.\bin\migrate.exe force 1 --confirm-existing-baseline
```

命令说明：

| 命令 | 用途 |
|---|---|
| `version` | 输出当前 migration metadata，格式为 `version=<n> dirty=<bool>`。 |
| `up` | 在非生产环境应用所有未执行的 migrations。 |
| `up --confirm-production` | 当 `APP_ENV=production` 时应用所有未执行的 migrations；生产环境必须显式使用该保护参数。 |
| `force 1 --confirm-existing-baseline` | 将已有且兼容的 V001 schema 登记为 version 1；只能配合 `docs/runbooks/database-baseline.md` 使用。 |

项目 CLI 没有暴露通用 `down` 命令。生产回滚不应依赖手动 down SQL，应走数据库恢复流程或通过新的 forward migration 修复。

## 环境变量

CLI 读取与应用相同的配置。至少需要设置：

```powershell
$env:APP_ENV = "production" # 或 development / staging
$env:DB_HOST = "<postgres-host>"
$env:DB_PORT = "5432"
$env:DB_USER = "<db-user>"
$env:DB_PASSWORD = "<db-password>"
$env:DB_NAME = "<db-name>"
$env:DB_SSLMODE = "require" # 生产通常为 require / verify-full；本地常用 disable
```

CLI 会根据这些变量拼接 PostgreSQL URL，并通过 `pgx/v5` driver 执行二进制中嵌入的 SQL migrations。

当前 migration 文件包括：

```text
000001_initial_schema.up.sql
000001_initial_schema.down.sql
000002_require_s256_pkce.up.sql
000002_require_s256_pkce.down.sql
```

## 执行前检查清单

对任何共享环境或生产类数据库执行 migration 前，都必须完成以下检查：

1. 确认当前 release / commit 正是计划部署的版本。
2. 从该版本构建 migration CLI：

   ```powershell
   go build -o bin/migrate.exe ./cmd/migrate
   ```

3. 确认数据库连接指向目标数据库，而不是本地库、测试库或错误环境：

   ```powershell
   .\bin\migrate.exe version
   ```

4. 生产环境必须提前获得维护窗口，并确认可恢复的数据库备份已经存在。
5. 暂停部署、schema-changing job、DDL-capable 管理会话等可能并发修改 schema 的操作。
6. 审查待执行的 SQL 文件，尤其是 migration 内置的阻断条件和不可逆风险。
7. 确认当前状态为 `dirty=false`。如果输出 `dirty=true`，立即停止，按本文的「Dirty 状态处理」执行。

## 非生产环境标准流程

适用于本地、CI、开发环境、测试环境、预发环境等 `APP_ENV != production` 的数据库。

### 1. 构建 CLI

```powershell
go build -o bin/migrate.exe ./cmd/migrate
```

### 2. 查看当前版本

```powershell
.\bin\migrate.exe version
```

常见输出示例：

```text
version=0 dirty=false
version=1 dirty=false
version=2 dirty=false
```

说明：

- `version=0 dirty=false`：当前没有已登记的 migration version。
- `dirty=false`：当前 migration metadata 干净，可以继续。
- `dirty=true`：上一次 migration 失败或中断，不允许继续盲目执行。

### 3. 执行 migration

```powershell
.\bin\migrate.exe up
```

该命令会执行二进制中嵌入的所有未执行 migrations。如果没有待执行 migration，底层 `ErrNoChange` 会被视为成功。

### 4. 验证版本

```powershell
.\bin\migrate.exe version
```

确认输出为预期最新版本，且必须是：

```text
dirty=false
```

### 5. 应用健康检查

migration 完成后，启动或重启 API 服务，并检查：

```text
GET /health -> { "status": "ok", "db": "ok", "redis": "ok" }
```

## 生产环境标准流程

生产环境必须使用显式确认参数。若 `APP_ENV=production`，直接运行 `up` 会失败。

### 1. 确认备份和维护窗口

执行前必须确认：

- 数据库已有可恢复备份。
- 维护窗口或变更窗口已经批准。
- 部署流程已暂停。
- 没有其他进程或人工会话正在执行 DDL。
- 当前 migration binary 对应的 release artifact 或 commit SHA 已记录到变更单。

### 2. 获取或构建 release binary

优先使用目标 release 产出的构建产物。若需要手动构建：

```powershell
go build -o bin/migrate.exe ./cmd/migrate
```

### 3. 确认目标库和当前状态

设置生产 `DB_*` 环境变量后执行：

```powershell
.\bin\migrate.exe version
```

只有满足以下条件才允许继续：

- 确认连接的是目标生产库。
- 输出为 `dirty=false`。
- 当前 version 与预期的迁移前版本一致。

### 4. 执行生产 migration

```powershell
.\bin\migrate.exe up --confirm-production
```

不要在生产环境使用不带确认参数的 `up`。当 `APP_ENV=production` 时，如果误执行：

```powershell
.\bin\migrate.exe up
```

CLI 会返回：

```text
migration up in production requires --confirm-production
```

### 5. 验证 migration metadata

```powershell
.\bin\migrate.exe version
```

确认：

- version 已变为预期最新版本；
- `dirty=false`。

### 6. 迁移后验证

完成 migration 后，执行约定的 smoke checks：

- API `/health` 返回 `db=ok` 和 `redis=ok`。
- 本次 migration 影响的登录、认证、OAuth 或其他关键流程在目标环境通过验证。
- 用只读 SQL spot-check 关键约束、索引或字段状态。
- 应用日志中没有 migration 相关启动错误或数据库错误。

## V001 Baseline 与普通 Migration 的区别

生产库若已经人工或历史方式存在 V001 schema，不应再执行 V001 `up`。此时需要做 baseline registration：

```powershell
.\bin\migrate.exe force 1 --confirm-existing-baseline
```

该命令只适用于 V001 baseline，并且必须遵循：

```text
docs/runbooks/database-baseline.md
```

禁止用 `force` 随意设置其他版本。

## V002 专项说明

V002 会将 `oauth_authorizations.code_challenge_method` 收紧为只允许 `S256`。

在已有数据库上执行 V002 前，建议先运行以下只读检查：

```sql
SELECT code_challenge_method, COUNT(*)
FROM oauth_authorizations
WHERE code_challenge_method <> 'S256'
GROUP BY code_challenge_method;
```

预期结果：无返回行。

如果返回了 `plain` 或其他非 `S256` 数据，必须停止。V002 的设计是遇到存量非 S256 授权码时直接失败，而不是静默改写数据。

后续处理方式需要走审批流程决定，例如：

- 等待这些授权码自然过期并清理；
- 在维护窗口内执行经过批准的数据修复；
- 编写单独的 forward migration 处理历史数据。

V002 应用后，以下插入在一次性测试数据库中应失败，因为 `plain` 已不再允许：

```sql
-- 不要在生产库中执行该写入示例；仅用于一次性测试数据库。
INSERT INTO oauth_authorizations (
    code, client_id, user_id, scopes, code_challenge, code_challenge_method, expires_at
)
VALUES ('manual-check', 1, 1, ARRAY['openid'], 'challenge', 'plain', NOW() + INTERVAL '10 minutes');
```

## Dirty 状态处理

`dirty=true` 表示某次 migration 执行失败、中断，或 metadata 更新过程中发生异常。

如果 `version` 输出 `dirty=true`：

1. 立即停止。
2. 不要盲目再次运行 `up`。
3. 不要手动修改 `schema_migrations` 表。
4. 不要使用任意 `force` 修状态；唯一例外是文档化的 V001 baseline 命令，并且必须严格遵循 baseline runbook。
5. 保存 CLI 输出、数据库日志、当前 version 和 dirty 状态。
6. 通过 incident / change 流程判断下一步：
   - 从备份恢复；
   - 人工修复部分 DDL；
   - 编写 forward migration；
   - 或在明确验证后执行受控修复命令。

## 失败响应

如果 migration 命令失败：

1. 停止继续执行 migration 命令。
2. 记录以下信息：
   - 执行的完整命令；
   - CLI 输出；
   - `APP_ENV`；
   - 当前 `version` 输出（如果安全可执行）；
   - 失败时段的数据库日志。
3. 不要在生产环境手写 down SQL。
4. 不要直接编辑 migration metadata。
5. 使用数据库备份恢复，或提交经过审查的 forward migration / data-fix 方案。

## 明确禁止事项

- 禁止在已经存在 V001 schema 的生产库上执行 V001 `up`。
- 禁止假设 API 容器启动时会自动迁移 schema。
- 禁止把生产数据库凭据传给测试命令。
- 禁止在 release binary 构建后再手改 embedded migration SQL。
- 禁止对任意版本使用 `force`。
- 禁止未经明确批准执行 SSH 或持久化服务器操作。
- 禁止在 `dirty=true` 时继续盲目执行 `up`。

## 快速命令速查

### 本地 / 开发 / 预发

```powershell
go build -o bin/migrate.exe ./cmd/migrate
.\bin\migrate.exe version
.\bin\migrate.exe up
.\bin\migrate.exe version
```

### 生产

```powershell
go build -o bin/migrate.exe ./cmd/migrate
.\bin\migrate.exe version
.\bin\migrate.exe up --confirm-production
.\bin\migrate.exe version
```

### 仅限已有 V001 生产库 baseline

```powershell
.\bin\migrate.exe version
.\bin\migrate.exe force 1 --confirm-existing-baseline
.\bin\migrate.exe version
```
