# SAST Link Backend V2 部署与配置方案

> 日期：2026-05-19
> 版本：v1.0

---

## 1. 部署架构

```
┌─────────────────────────────────────────────────────────────┐
│                        用户浏览器                             │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Caddy 反向代理 (80/443)                                     │
│  ├── /apis/* → sast-link-backend-v2:8080                   │
│  └── / → sast-link-next (静态文件)                          │
└──────────────────────────┬──────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
│  sast-link-v2   │ │ PostgreSQL  │ │     Redis       │
│   (Go + Gin)    │ │    (15)     │ │      (7)        │
│    :8080        │ │    :5432    │ │    :6379        │
└─────────────────┘ └─────────────┘ └─────────────────┘
```

---

## 2. Docker Compose

```yaml
version: "3.8"

services:
  postgres:
    image: postgres:15-alpine
    container_name: sastlink-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-sastlink}
      POSTGRES_USER: ${POSTGRES_USER:-sastlink}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./migrations:/migrations
    ports:
      - "127.0.0.1:${POSTGRES_PORT:-5432}:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-sastlink}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - sastlink

  redis:
    image: redis:7-alpine
    container_name: sastlink-redis
    restart: unless-stopped
    command: >
      redis-server
      --requirepass ${REDIS_PASSWORD}
      --maxmemory 256mb
      --maxmemory-policy allkeys-lru
    volumes:
      - redisdata:/data
    ports:
      - "127.0.0.1:${REDIS_PORT:-6379}:6379"
    healthcheck:
      test: ["CMD-SHELL", "redis-cli -a \"$REDIS_PASSWORD\" ping | grep PONG"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - sastlink

  api:
    build:
      context: .
      dockerfile: docker/Dockerfile
    container_name: sastlink-api
    restart: unless-stopped
    environment:
      # 应用
      APP_ENV: ${APP_ENV:-production}
      APP_PORT: ${APP_PORT:-8080}
      LOG_LEVEL: ${LOG_LEVEL:-info}

      # 数据库
      DATABASE_URL: postgres://${POSTGRES_USER:-sastlink}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-sastlink}?sslmode=${DB_SSLMODE:-disable}

      # Redis
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379/0

      # JWT
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}
      JWT_EXPIRY: ${JWT_EXPIRY:-168h}

      # 邮件
      SMTP_HOST: ${SMTP_HOST}
      SMTP_PORT: ${SMTP_PORT:-587}
      SMTP_USERNAME: ${SMTP_USERNAME}
      SMTP_PASSWORD: ${SMTP_PASSWORD}
      SMTP_FROM: ${SMTP_FROM}
      SMTP_USE_TLS: ${SMTP_USE_TLS:-true}

      # OAuth 客户端配置
      OAUTH_FEISHU_CLIENT_ID: ${OAUTH_FEISHU_CLIENT_ID}
      OAUTH_FEISHU_CLIENT_SECRET: ${OAUTH_FEISHU_CLIENT_SECRET}
      OAUTH_GITHUB_CLIENT_ID: ${OAUTH_GITHUB_CLIENT_ID}
      OAUTH_GITHUB_CLIENT_SECRET: ${OAUTH_GITHUB_CLIENT_SECRET}
      OAUTH_MICROSOFT_CLIENT_ID: ${OAUTH_MICROSOFT_CLIENT_ID}
      OAUTH_MICROSOFT_CLIENT_SECRET: ${OAUTH_MICROSOFT_CLIENT_SECRET}
      OAUTH_QQ_CLIENT_ID: ${OAUTH_QQ_CLIENT_ID}
      OAUTH_QQ_CLIENT_SECRET: ${OAUTH_QQ_CLIENT_SECRET}

      # COS / 对象存储
      COS_BUCKET: ${COS_BUCKET}
      COS_REGION: ${COS_REGION}
      COS_SECRET_ID: ${COS_SECRET_ID}
      COS_SECRET_KEY: ${COS_SECRET_KEY}
      COS_ENDPOINT: ${COS_ENDPOINT}

    ports:
      - "127.0.0.1:${API_PORT:-8080}:8080"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - sastlink
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:8080/ping || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

volumes:
  pgdata:
  redisdata:

networks:
  sastlink:
    driver: bridge
```

---

## 3. Dockerfile

```dockerfile
# Build stage
FROM golang:1.26.3-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /app/bin/api \
    ./cmd/api

# Runtime stage
FROM alpine:3.21

WORKDIR /app

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Copy binary from builder
COPY --from=builder /app/bin/api /app/api

# Copy migration files
COPY --from=builder /app/migrations /app/migrations

# Create non-root user
RUN adduser -D -g '' appuser
USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/api"]
```

---

## 4. 环境变量配置

### 4.1 必需环境变量

| 变量 | 说明 | 示例 |
|------|------|------|
| `JWT_SECRET_KEY` | JWT 签名密钥（256-bit+ 随机串） | `$(openssl rand -hex 32)` |
| `POSTGRES_PASSWORD` | PostgreSQL 密码 | — |
| `REDIS_PASSWORD` | Redis 密码 | — |

### 4.2 数据库配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `POSTGRES_DB` | `sastlink` | 数据库名 |
| `POSTGRES_USER` | `sastlink` | 数据库用户 |
| `POSTGRES_PORT` | `5432` | 主机映射端口 |
| `DB_SSLMODE` | `disable` | 数据库 SSL 模式（生产环境改为 `require` 或 `verify-full`） |

### 4.3 Redis 配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `REDIS_PORT` | `6379` | 主机映射端口 |

### 4.4 JWT 配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `JWT_EXPIRY` | `168h` | Login Token 有效期（7天） |
| `INITIAL_SUPER_ADMIN_UID` | — | 初始超级管理员学号（首次启动时自动创建） |

### 4.5 邮件配置（自行配置，不默认飞书）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SMTP_HOST` | — | SMTP 服务器地址 |
| `SMTP_PORT` | `587` | SMTP 端口 |
| `SMTP_USERNAME` | — | SMTP 用户名 |
| `SMTP_PASSWORD` | — | SMTP 密码 |
| `SMTP_FROM` | — | 发件人地址 |
| `SMTP_USE_TLS` | `true` | 是否使用 TLS |

**飞书 SMTP 配置示例**：
```bash
SMTP_HOST=smtp.feishu.cn
SMTP_PORT=465
SMTP_USERNAME=your-bot@feishu.cn
SMTP_PASSWORD=your-app-password
SMTP_FROM=noreply@sast.fun
SMTP_USE_TLS=true
```

**Gmail SMTP 配置示例**：
```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=noreply@sast.fun
SMTP_USE_TLS=true
```

### 4.6 OAuth 客户端配置

| 变量 | 说明 |
|------|------|
| `OAUTH_FEISHU_CLIENT_ID` | 飞书自建应用 App ID |
| `OAUTH_FEISHU_CLIENT_SECRET` | 飞书自建应用 App Secret |
| `OAUTH_GITHUB_CLIENT_ID` | GitHub OAuth App Client ID |
| `OAUTH_GITHUB_CLIENT_SECRET` | GitHub OAuth App Client Secret |
| `OAUTH_MICROSOFT_CLIENT_ID` | Microsoft Entra ID Client ID |
| `OAUTH_MICROSOFT_CLIENT_SECRET` | Microsoft Entra ID Client Secret |
| `OAUTH_QQ_CLIENT_ID` | QQ 开放平台 App ID |
| `OAUTH_QQ_CLIENT_SECRET` | QQ 开放平台 App Key |

### 4.7 对象存储配置

| 变量 | 说明 |
|------|------|
| `COS_BUCKET` | 存储桶名称 |
| `COS_REGION` | 存储桶区域 |
| `COS_SECRET_ID` | SecretId |
| `COS_SECRET_KEY` | SecretKey |
| `COS_ENDPOINT` | 自定义 Endpoint（可选） |

---

## 5. 健康检查

### 5.1 Liveness Probe

```
GET /ping
Response: "pong" (text/plain)
```

### 5.2 Readiness Probe

```
GET /health
Response:
{
  "status": "ok",
  "version": "1.0.0",
  "checks": {
    "database": "ok",
    "redis": "ok"
  },
  "timestamp": "2026-05-19T12:00:00Z"
}
```

---

## 6. 数据库迁移

### 6.1 首次部署

```bash
# 1. 启动基础设施
docker-compose up -d postgres redis

# 2. 等待数据库就绪
until docker-compose exec postgres pg_isready -U sastlink; do sleep 1; done

# 3. 执行迁移
docker-compose run --rm api /app/api migrate up

# 4. 启动应用
docker-compose up -d api
```

### 6.2 从老数据库迁移

```bash
# 1. 备份老数据库
pg_dump -h old-host -U old-user old-db > backup.sql

# 2. 在新环境恢复基础数据
psql -h localhost -U sastlink sastlink < backup.sql

# 3. 执行数据清洗迁移
migrate -path ./migrations -database "postgres://..." up

# 4. 验证数据完整性
make migrate-verify
```

### 6.3 Makefile 常用命令

```makefile
.PHONY: build run test migrate-up migrate-down migrate-verify docker-up docker-down

build:
	go build -o bin/api ./cmd/api

run:
	go run ./cmd/api

test:
	go test -v -race -cover ./...

migrate-up:
	migrate -path ./migrations -database "$(DATABASE_URL)" up

migrate-down:
	migrate -path ./migrations -database "$(DATABASE_URL)" down 1

migrate-verify:
	@echo "Running migration verification..."
	@go run ./scripts/verify_migration.go

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down -v

lint:
	golangci-lint run

fmt:
	go fmt ./...
```

---

## 7. 生产环境检查清单

### 7.1 部署前

- [ ] `JWT_SECRET_KEY` 已设置为 256-bit+ 随机串（`openssl rand -hex 32`）
- [ ] 所有 OAuth 客户端密钥已从环境变量注入，未硬编码
- [ ] SMTP 配置已验证可正常发件
- [ ] PostgreSQL 密码强度足够
- [ ] Redis 已启用密码认证
- [ ] `.env` 文件已加入 `.gitignore`

### 7.2 部署后

- [ ] `/ping` 返回 `pong`
- [ ] `/health` 返回所有 checks 为 `ok`
- [ ] 注册流程端到端测试通过
- [ ] 登录流程端到端测试通过
- [ ] OAuth 登录（飞书/GitHub）测试通过
- [ ] 邮件发送测试通过
- [ ] 日志中无敏感信息泄露

---

## 8. 开发环境搭建

```bash
# 1. 克隆仓库
git clone https://github.com/NJUPT-SAST/sast-link-backend-v2.git
cd sast-link-backend-v2

# 2. 复制环境变量模板
cp .env.example .env
# 编辑 .env 填入本地配置

# 3. 启动基础设施
docker-compose up -d postgres redis

# 4. 执行迁移
make migrate-up

# 5. 运行应用
go run ./cmd/api

# 6. 验证
 curl http://localhost:8080/ping
```

---

*文档结束。*
