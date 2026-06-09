# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Status

SAST Link Backend V2 is the backend design repository for SAST's unified identity/authentication center and personnel information system. The backend implementation code has been removed; the repository currently keeps product, API, database, environment, Docker, and CI reference material for a future rebuild.

Do not assume application source exists yet. At the time this guide was written, there is no `go.mod`, `go.sum`, `cmd/api`, package tree, migrations directory, lint config, or test suite in the working tree.

## Current Commands

Use these commands against the current documentation/config skeleton:

```powershell
# Inspect tracked project files
git ls-files

# Validate the Docker Compose file syntax and resolved environment defaults
# Expect warnings when required environment variables are unset; warnings do not by themselves mean the compose file is invalid.
docker compose config

# Manually run the placeholder CI workflow in GitHub Actions
# The workflow only checks out the repo and reports that implementation code was removed.
```

The current repository has no runnable build, lint, or test command. `docker build -f docker/Dockerfile .` is a deployment reference and will fail until Go implementation files such as `go.mod`, `go.sum`, `cmd/api`, and `docs/migrations` are restored.

## Commands Once Go Implementation Is Restored

The preserved design targets Go `1.26.4`, Gin, GORM, PostgreSQL 16+, Redis 8+, and testcontainers-go. Once `go.mod` and source code are reintroduced, expect the normal Go workflow to become:

```powershell
# Download modules
go mod download

# Build the API binary expected by docker/Dockerfile
go build -o bin/api ./cmd/api

# Run all tests
go test ./...

# Run a single package test
go test ./path/to/package -run TestName

# Run security scans matching .github/workflows/security.yml
go run github.com/securego/gosec/v2/cmd/gosec@latest -fmt text ./...
govulncheck ./...
```

Update this section when the implementation lands if the actual commands differ.

## Source Of Truth Documents

- `README.md`: repository status and retained skeleton inventory.
- `docs/SAST Link v2 PRD.md`: product and architecture source of truth, including target tech stack, token lifecycle, Redis key design, security requirements, observability, and implementation order.
- `docs/API文档.md`: human-readable API contract, response envelopes, business error codes, and endpoint behavior.
- `docs/openapi.yaml`: machine-readable OpenAPI 3.0.1 contract. Keep it aligned with `docs/API文档.md` when endpoints change.
- `docs/psql-db-design.md`: PostgreSQL schema design, enum values, indexes, triggers, token-family cascade revocation flow, and pg_cron cleanup jobs.
- `.env.example`: environment variable names and defaults expected by the future service.
- `docker-compose.yml` and `docker/Dockerfile`: deployment reference for an API container connected to external PostgreSQL and Redis Docker networks.

## Target Architecture

The intended service is a stateless Go API serving SAST Link v2 at `https://link.sast.fun/v2`. It is both an internal authentication service and an OAuth 2.1 / OIDC Provider.

Core domains:

- Internal auth: email/password login, GitHub OAuth login, Lark OAuth login, registration, password change/reset, logout, and token refresh.
- User/profile management: `user` owns identity and permission fields; `profile` owns display-card fields.
- Third-party identities: `identities` binds GitHub, Lark, and additional email logins. Lark stores `union_id` as `provider_id`, not `open_id`.
- OAuth/OIDC provider: authorization code + PKCE, refresh token grant, revoke, discovery, JWKS, UserInfo, and ID Token issuance.
- Admin: user list/detail/update/soft-delete/restore, OAuth client management, and audit log query.
- Operations: health check, structured JSON logs, PostgreSQL data retention via pg_cron, Redis-backed rate limiting/session helpers.

Important design constraints:

- Standard non-OAuth endpoints use `{ "code": 0, "message": "ok", "data": ... }` response envelopes.
- OAuth `/oauth/authorize`, `/oauth/token`, and `/oauth/revoke` follow RFC 6749 formats instead of the standard envelope.
- OIDC UserInfo errors follow RFC 6750-style `invalid_token` responses.
- Access tokens are RS256 JWTs with `kid`, `jti`, `sub`, `role`, `state`, `token_version`, and scopes; JWKS exposes public keys.
- Refresh tokens are opaque strings stored as HMAC-SHA256 hashes and rotated by `family_id` + `sequence`.
- Authorization code replay or refresh-token replay should revoke the whole token family across access and refresh metadata.
- Password hashing is specified as PBKDF2-SHA512 with 600,000 iterations and a 16-byte random salt.
- Registration/login email domains are limited to `@njupt.edu.cn` and `@sast.fun`; the DB trigger derives `email_type` from the domain.
- Lark login is limited to the SAST tenant.

## Data Model Big Picture

The core PostgreSQL tables are:

- `user`: primary identity, role, state machine, login email, password hash, and `token_version` for global token invalidation.
- `profile`: one-to-one display profile for cards and public fields.
- `identities`: third-party login bindings with provider-specific JSONB metadata and uniqueness constraints.
- `oauth_clients`: first-party and third-party clients, redirect URIs, grant types, scopes, active state.
- `oauth_authorizations`: short-lived authorization codes with PKCE data, nonce, single-use state, and `family_id`.
- `oauth_access_tokens`: JWT metadata for revocation/audit, including `token_id`/`jti` and `family_id`.
- `oauth_refresh_tokens`: hashed refresh tokens with `family_id` and monotonic `sequence` for rotation/replay detection.
- `audit_logs`: auth/admin audit trail retained for 90 days.

The user state machine is `njupter -> on_sast -> retired_sast`; any non-deleted state can move to `is_deleted`, and restore returns to `njupter`.

## Redis Design Anchors

Redis is used for short-lived and operational state, not durable source-of-truth data. The PRD defines keys for verification codes, rate limits, devices, token blacklist, OAuth state, registration state, login codes, login failures, `token_version` cache, Register-Tickets, and Bind-Tickets. Most flows require one-time consumption via GetDel semantics.

When rebuilding flows, preserve the double binding between `registration_state` and the original OAuth `state`; `registration_state` is only for new-user registration and must not be accepted as an authenticated account-binding mechanism.

## Deployment Notes

`docker-compose.yml` defines one `api` service listening on `127.0.0.1:${API_PORT:-8080}:8080` with external `postgres` and `redis` networks. The health check expects:

```text
GET /health -> { "status": "ok", "db": "ok", "redis": "ok" }
```

The Dockerfile expects a Go API at `./cmd/api` and copies `docs/migrations` into the runtime image. If the future implementation uses a different migration path or entrypoint, update both `docker/Dockerfile` and this guide together.

## CI And Security

`.github/workflows/ci.yml` is currently a manual placeholder. `.github/workflows/security.yml` runs on pushes, pull requests, and weekly schedule, and expects a Go module so it can run:

```powershell
go run github.com/securego/gosec/v2/cmd/gosec@latest -fmt text ./...
govulncheck ./...
```

Until implementation code returns, security workflow jobs may fail because there is no Go module to scan.
