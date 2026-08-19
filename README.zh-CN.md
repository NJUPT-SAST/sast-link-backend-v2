# SAST Link Backend V2

SAST 统一身份认证中心与人员信息管理系统

<div align="center">

[![CI](https://github.com/NJUPT-SAST/sast-link-backend-v2/actions/workflows/ci.yml/badge.svg)](https://github.com/NJUPT-SAST/sast-link-backend-v2/actions/workflows/ci.yml)
[![Security](https://github.com/NJUPT-SAST/sast-link-backend-v2/actions/workflows/security.yml/badge.svg)](https://github.com/NJUPT-SAST/sast-link-backend-v2/actions/workflows/security.yml)
[![Go](https://img.shields.io/badge/Go-1.26.6-blue.svg)](https://go.dev)
[![GitHub stars](https://img.shields.io/github/stars/NJUPT-SAST/sast-link-backend-v2.svg)](https://github.com/NJUPT-SAST/sast-link-backend-v2)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[简体中文](README.zh-CN.md) | [English](README.md)

</div>

## 快速开始

```bash
cp .env.example .env
# 生成 Ed25519 私钥，填入 .env 的 JWT_SECRET_KEY
openssl genpkey -algorithm ED25519 -out jwt.key
docker compose up -d
```

compose 会启动 PostgreSQL 与 Redis、自动执行数据库迁移。验证：

```bash
curl http://127.0.0.1:8080/health
# {"status":"ok","db":"ok","redis":"ok"}
```

## 特性

- **登录与账号**：邮箱密码登录、两步邮箱注册、找回密码，支持 GitHub 与飞书登录
- **标准认证协议**：OAuth 2.1 / OIDC，第三方应用可接入授权登录、令牌刷新与用户信息
- **账号安全**：argon2id 密码哈希、Ed25519 令牌签名，改密可吊销全部会话
- **用户自助**：个人资料、第三方账号绑定、设备管理、头像上传
- **管理后台**：用户管理、OAuth 客户端配置、操作审计日志
- **运维**：PostgreSQL 16 + Redis 8，Compose 一键启动，内置健康检查

## 文档

- [API 文档](./docs/API文档.md)：接口定义、响应格式与业务错误码
- [OpenAPI 规范](./docs/openapi.yaml)：机器可读的接口契约

其余文档——产品需求、数据库设计、部署指南——位于 [docs/](./docs)。

## 开发

```bash
go test -race -shuffle=on -pgo=off ./...
golangci-lint run ./...
```

## 贡献与安全

[贡献指南](./CONTRIBUTING.md) · [行为准则](./CODE_OF_CONDUCT.md) · [安全策略](./SECURITY.md)

## 许可证

[MIT](./LICENSE) © NJUPT SAST
