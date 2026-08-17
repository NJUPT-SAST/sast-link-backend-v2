# SAST Link Backend V2

SAST Link is the unified identity authentication center and personnel information management system.

<div align="center">

[![CI](https://github.com/NJUPT-SAST/sast-link-backend-v2/actions/workflows/ci.yml/badge.svg)](https://github.com/NJUPT-SAST/sast-link-backend-v2/actions/workflows/ci.yml)
[![Security](https://github.com/NJUPT-SAST/sast-link-backend-v2/actions/workflows/security.yml/badge.svg)](https://github.com/NJUPT-SAST/sast-link-backend-v2/actions/workflows/security.yml)
[![Go](https://img.shields.io/badge/Go-1.26.6-blue.svg)](https://go.dev)
[![GitHub stars](https://img.shields.io/github/stars/NJUPT-SAST/sast-link-backend-v2.svg)](https://github.com/NJUPT-SAST/sast-link-backend-v2)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[简体中文](README.zh-CN.md) | [English](README.md)

</div>

## Quick Start

```bash
cp .env.example .env
# Generate an Ed25519 private key and paste it into JWT_SECRET_KEY in .env
openssl genpkey -algorithm ED25519 -out jwt.key
docker compose up -d
```

Compose starts PostgreSQL and Redis and applies database migrations automatically. Verify:

```bash
curl http://127.0.0.1:8080/health
# {"status":"ok","db":"ok","redis":"ok"}
```

## Features

- **Login & accounts**: password login, two-step email registration, password reset, GitHub and Feishu sign-in
- **Standard auth protocol**: OAuth 2.1 / OIDC for third-party apps to integrate login, token refresh, and user info
- **Account security**: argon2id password hashing, Ed25519 token signing, revoke all sessions on password change
- **Self-service**: profile management, third-party account binding, authorized-apps management, device management, avatar upload
- **Admin console**: user management, OAuth client configuration, audit logs, console overview stats
- **Operations**: PostgreSQL 16 + Redis 8, one-command Compose startup, built-in health check

## Documentation

- [API Documentation](./docs/API文档.md): endpoints, response format, and business error codes
- [OpenAPI Specification](./docs/openapi.yaml): machine-readable API contract

Other documents — product requirements, database design, deployment guides — live in [docs/](./docs).

## Development

```bash
go test -race -shuffle=on -pgo=off ./...
golangci-lint run ./...
```

## Contributing & Security

[Contributing Guide](./CONTRIBUTING.md) · [Code of Conduct](./CODE_OF_CONDUCT.md) · [Security Policy](./SECURITY.md)

## License

[MIT](./LICENSE) © NJUPT SAST
