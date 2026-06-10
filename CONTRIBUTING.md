# 贡献指南

## 开发环境

- **Go**：1.26.4
- **数据库**：PostgreSQL 16+
- **缓存**：Redis 8+

复制 `.env.example` 为 `.env`，填入本地连接信息。`.env` 文件已被 git 忽略。

```powershell
cp .env.example .env
```

启动本地 PostgreSQL 和 Redis 实例（Docker 或原生均可）。应用会通过 `.env` 中配置的主机和端口连接它们。

## 代码质量

### Pre-commit Hook

本项目使用 `pre-commit` 框架在每次 `git commit` 前自动执行格式化和基础检查。

```powershell
# 安装 pre-commit（仅需一次）
pip install pre-commit

# 安装 git hook
pre-commit install

# 手动对所有文件运行（首次或调试时）
pre-commit run --all-files
```

Hook 配置见 `.pre-commit-config.yaml`，当前包含：

| Hook | 作用 |
|------|------|
| `trailing-whitespace` | 删除行尾空白 |
| `end-of-file-fixer` | 文件以单个空行结尾 |
| `check-yaml` | YAML 语法校验 |
| `check-merge-conflict` | 拦截残留的合并冲突标记 |
| `go-fmt` | `gofmt -s` 格式化 |
| `go-imports` | import 排序与未使用 import 清理 |
| `go-vet` | Go 官方静态分析 |

### golangci-lint

Hook 覆盖了快速检查，深度 lint 仍需手动运行。规则集定义在 `.golangci.yml`。

```powershell
# 安装 golangci-lint（仅需一次）
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

# 运行 lint
golangci-lint run ./...
```

CI 中的 lint job 必须在合入前通过。建议推送前本地先跑，避免来回修复。

强制规则速查：

| 规则 | 检查内容 |
|------|---------|
| `govet` | Go 官方静态分析 |
| `staticcheck` | 深层 bug、性能、简化检查 |
| `errcheck` | 未处理的 error 返回值 |
| `gofmt` / `goimports` | 格式一致性与 import 排序 |
| `gosec` | 安全问题（SQL 注入、硬编码密钥等） |
| `bodyclose` / `sqlclosecheck` | 未关闭的 HTTP body 和 DB 资源 |
| `exported` | 所有导出符号必须有 godoc 注释 |

## 测试

### 编写测试

- 使用 Go 标准库 `testing` 包。
- 涉及 PostgreSQL 或 Redis 的集成测试，推荐使用 [testcontainers-go](https://golang.testcontainers.org/) 或依赖 `.github/workflows/ci.yml` 中配置的 CI service containers（Postgres 16 + Redis 8）。
- 测试必须支持并发运行和任意顺序执行，禁止测试函数之间依赖共享全局状态。

### 运行测试

```powershell
# 全量测试（竞态检测 + 覆盖率）
go test -race -shuffle=on -coverprofile=coverage.out -covermode=atomic ./...

# 单包测试
go test -race -shuffle=on ./path/to/package -run TestName
```

CI 中所有测试均携带：
- `-race` — 数据竞争检测。本项目 token 刷新、设备管理、限流等均为并发场景，此项不可省略
- `-shuffle=on` — 随机化测试执行顺序，暴露测试间隐式依赖

### 测试要求

- 新功能必须包含 Happy Path 和至少一个错误/边界用例的测试。
- Bug 修复必须包含一条回归测试：修复前失败，修复后通过。
- 不允许出现不稳定测试（flaky test）。如果某条测试偶发失败，须定位根因并修复后才能合入。

## 提交规范

遵循 [Conventional Commits](https://www.conventionalcommits.org/)：

```
<type>(<scope>): <description>
```

类型：`feat`、`fix`、`docs`、`refactor`、`test`、`chore`、`perf`、`ci`

示例：

```
feat(auth): 实现 PBKDF2-SHA512 密码哈希
fix(token): 通过 family_id 检测 refresh token 重放
docs(readme): 补充本地开发环境搭建说明
chore(deps): 升级 golang.org/x/crypto 至 v0.35.0
```

保持提交原子化——每次提交只包含一个逻辑变更。如需修正上一个提交，使用 rebase 而非追加"修复笔误"类提交。

## Pull Request 流程

1. 从 `main` 分支创建，使用描述性分支名（如 `feat/oauth-pkce`、`fix/token-race`）。
2. 保持改动聚焦。如果 PR 涉及多个不相关变更，请拆分。
3. 确保 `golangci-lint run ./...` 和 `go test -race -shuffle=on ./...` 在本地通过。
4. CI（当前代码骨架阶段通过 `workflow_dispatch` 手动触发）必须通过。
5. PR 描述写清楚：改了什么、为什么改、如何验证。
6. 至少一名团队成员 review 通过后方可合入。

## 项目结构

新增代码请遵循 Go 社区惯例：

```
cmd/api/           应用入口
internal/          私有包（auth、profile、oauth、admin、middleware 等）
docs/              设计文档与 OpenAPI 规范
```

避免循环引用。领域逻辑放在独立包内，不依赖传输层（Gin handler）。
