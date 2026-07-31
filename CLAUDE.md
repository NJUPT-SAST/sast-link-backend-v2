# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Status

SAST Link Backend V2 is the backend for SAST's unified identity/authentication center and personnel information system. The current implementation establishes the Go module, HTTP service skeleton, V001–V005 PostgreSQL schema migrations (including the built-in `sast-link-web` first-party client, the token-blacklist outbox, and the cross-table email uniqueness triggers), persistence entities and Auth repositories, authentication primitives, the internal session flow (password login, refresh rotation/replay handling, logout, JWT middleware, durable Redis blacklist delivery), the SMTP mailer, the two-step email registration flow, password change/reset with whole-user token revocation and authorization-code invalidation, third-party email binding with Bind-Tickets, self-service profile management (profile read/edit, identity listing, unbind with password confirmation, public display card), the OAuth 2.1 / OIDC provider, and the admin console (OAuth client registry, user management, audit-log queries). PostgreSQL 16 and Redis integration tests use Testcontainers. Avatar upload, third-party OAuth login, device management, and pg_cron operations remain to be implemented.

`cmd/api` connects PostgreSQL and Redis and serves health, the public card endpoint `GET /card/:id`, and the internal auth endpoints: `POST /user/login`, `POST /auth/refresh`, `POST /auth/register/send-code`, `POST /auth/register/verify-code`, `POST /auth/register`, `POST /auth/forgot-password/send-code`, `POST /auth/reset-password`, and — behind the JWT middleware — `POST /auth/logout`, `POST /auth/change-password`, `GET /user/profile`, `PUT /user/profile`, `GET /user/identities`, `POST /user/identities/email`, `POST /user/identities/email/verify`, and `DELETE /user/identities/:id`.

It also serves the OAuth 2.1 / OIDC provider: `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`, `GET /oauth/authorize` (unauthenticated, rate limited per IP), `POST /oauth/token`, `POST /oauth/revoke`, `GET /userinfo` and `POST /userinfo` (any authenticated client — `/userinfo` authenticates inline via `AuthenticateAnyClient`, deliberately skipping the `azp` gate that would reject the third-party tokens it exists to serve), and — behind the JWT middleware — `POST /oauth/authorize/consent`. Behind JWT middleware plus an admin role check: `GET`/`POST /admin/oauth-clients`, `PUT /admin/oauth-clients/:id`, `PUT`/`DELETE /admin/users/:id`, `PUT /admin/users/:id/restore`, and `GET /admin/audit-logs`. Behind JWT middleware plus an admin-or-lecturer check (`adminhandler.ReaderRoles`): `GET /admin/users` and `GET /admin/users/:id`. The `/admin` group carries authentication only; each route names its own role gate, so adding one without a gate leaves it ungated rather than defaulting to admin — always pass one explicitly.

`docs/openapi.yaml` documents eight paths that are not registered yet, so treat it as the target contract rather than an inventory: the third-party login flow (`/oauth/github`, `/oauth/github/callback`, `/oauth/lark`, `/oauth/lark/callback`, `/oauth/exchange-code`, `/user/identities/github`, `/user/identities/lark`) and `/user/avatar`. The admin console is now fully registered, but its implementation deliberately tightens the contract in three places — see the status note at the top of `docs/API文档.md` §6: `PUT /admin/users/:id` refuses `state: is_deleted` (422), `email_type` is only accepted alongside a matching `login_email` (400), and `page_size` is capped at 100 everywhere.

It never performs DDL or schema migrations at startup. `cmd/migrate` is the only command that inspects or changes schema migration state.

## Current Commands

The project targets Go `1.26.5`, Gin, GORM, PostgreSQL 16+, Redis 8+, and testcontainers-go. Full integration tests provision PostgreSQL 16 through Testcontainers and require Docker.

```powershell
# Download modules
go mod download

# Run all tests with race detection, randomized execution order, and coverage
go test -race -shuffle=on -coverprofile=coverage.out -covermode=atomic ./...

# Run lint
golangci-lint run ./...

# Build the API and migration CLI
go build -o bin/api.exe ./cmd/api
go build -o bin/migrate.exe ./cmd/migrate

# Inspect and apply schema migrations (cmd/migrate is the only migration runner)
.\bin\migrate.exe version
.\bin\migrate.exe up
```

For a production database that already has the V001 schema, follow `docs/runbooks/database-baseline.md`. V001 already exists in production: do not run V001 `up` there. The guarded baseline command is `.\bin\migrate.exe force 1 --confirm-existing-baseline` after the runbook's preflight checks. Future production migrations require the explicit `.\bin\migrate.exe up --confirm-production` form.

`docker-compose.yml` runs a prebuilt API image through `API_IMAGE` or the default `sastlink-api:current` tag.

## Source Of Truth Documents

- `README.md`: current implementation inventory and entry points.
- `docs/SAST Link v2 PRD.md`: product and architecture source of truth, including implementation tracking.
- `docs/API文档.md`: human-readable API contract, response envelopes, business error codes, and endpoint behavior.
- `docs/openapi.yaml`: machine-readable OpenAPI 3.0.1 contract. Keep it aligned with `docs/API文档.md` when endpoints change.
- `docs/psql-db-design.md`: PostgreSQL schema design, enum values, indexes, triggers, token-family cascade revocation flow, and planned pg_cron cleanup jobs.
- `docs/runbooks/database-baseline.md`: V001 baseline procedure for the pre-existing production schema.
- `migrations/`: embedded versioned SQL migrations, including V002's S256-only PKCE constraint.
- `.env.example`: environment variable names and defaults expected by the service.
- `docker-compose.yml`: runtime reference for an API container connected to external PostgreSQL and Redis Docker networks.
- `.golangci.yml`: golangci-lint rule set.
- `.pre-commit-config.yaml`: pre-commit hook definitions.
- `CONTRIBUTING.md`: contribution guide covering environment setup, lint, tests, commit convention, and PR workflow.

## Target Architecture

The intended service is a stateless Go API serving SAST Link v2 at `https://link.sast.fun/v2`. It is both an internal authentication service and an OAuth 2.1 / OIDC Provider.

Core domains:

- Internal auth: email/password login, GitHub OAuth login, Lark OAuth login, registration, password change/reset, logout, and token refresh.
- User/profile management: `user` owns identity and permission fields; `profile` owns display-card fields.
- Third-party identities: `identities` binds GitHub, Lark, and additional email logins. Lark stores `union_id` as `provider_id`, not `open_id`.
- OAuth/OIDC provider: authorization code + PKCE, refresh token grant, revoke, discovery, JWKS, UserInfo, and ID Token issuance.
- Admin: user list/detail/update/soft-delete/restore, OAuth client management, and audit log query.
- Operations: health check, structured JSON logs, planned PostgreSQL data retention via pg_cron, and Redis-backed rate limiting/session helpers.

Important design constraints:

- Standard non-OAuth endpoints use `{ "code": 0, "message": "ok", "data": ... }` response envelopes.
- OAuth `/oauth/authorize`, `/oauth/token`, and `/oauth/revoke` follow RFC 6749 formats instead of the standard envelope.
- OIDC UserInfo errors follow RFC 6750-style `invalid_token` responses.
- Access tokens are RS256 JWTs with `kid`, `jti`, `sub`, `role`, `state`, `token_version`, and the canonical OAuth/OIDC `scope` claim; supported scopes are `openid`, `profile`, and `email`, with `openid` required and canonicalized before signing or persistence. JWKS exposes public keys.
- Refresh tokens are opaque strings stored as HMAC-SHA256 hashes and rotated by `family_id` + `sequence`.
- Authorization code replay or refresh-token replay should revoke the whole token family across access and refresh metadata.
- Password hashing is specified as PBKDF2-SHA512 with 600,000 iterations and a 16-byte random salt.
- Registration/login email domains are limited to `@njupt.edu.cn` and `@sast.fun`; the DB trigger derives `email_type` from the domain. `auto_set_email_type` only fires when `login_email` is in the UPDATE column list, so any write path exposing `email_type` on its own must validate it against the address rather than trusting it.
- `internal/validate` owns the rules more than one service must apply identically: the V001 column widths, the login-email domain list, the email format guard, and the C0/C1 control-character test. Do not re-derive any of them locally. A second copy that is even slightly weaker produces a value one path accepts and another rejects — an admin-written `login_email` containing NBSP or a zero-width space renders as ordinary in the console while every login attempt fails on a difference nobody can see.
- Lark login is limited to the SAST tenant.
- Closing an account, demoting a user, and disabling a client are "cut access now" operations: each revokes the affected tokens in the same transaction that flips the flag. The refresh flow does not compare `token_version`, so a state change without revocation leaves live refresh tokens able to mint fresh access tokens.
- Invariants that are a count over other rows (the last active admin) cannot be checked before the write: PostgreSQL cannot lock an aggregate, so concurrent writers both read a safe count. Take `pg_advisory_xact_lock` on a shared key inside the writing transaction, as V005 does for cross-table email uniqueness and `repository.adminLockKey` does for the admin guard.

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

Redis is used for short-lived and operational state, not durable source-of-truth data. The PRD defines keys for verification codes, rate limits, devices, token blacklist, OAuth state, registration state, login codes, login failures, Register-Tickets, and Bind-Tickets. Most flows require one-time consumption via GetDel semantics. `token_version` is deliberately not cached in Redis: the auth middleware already reads it from the same DB query that fetches access-token revocation state.

Every Redis-backed check must declare its behavior when Redis is unavailable, following one of two classes:

- **Fail-closed (Redis is the only store)**: verification codes, OAuth `state`, `registration_state`, `login_code`, Register/Bind-Tickets, and idempotency keys. A missing value cannot be treated as valid, so the flow must be rejected and restarted by the user.
- **Fail-open (PostgreSQL is authoritative, or loss only widens a rate window)**: the JTI blacklist, login-failure counters/lockout, and endpoint rate limits. These log at WARN and continue. The JTI blacklist is safe to skip because every blacklisted JTI is written in the same transaction that sets `oauth_access_tokens.revoked_at`, and the auth middleware always performs that DB check.

Do not make a fail-open dependency return `ErrInternal`; that turns an optional cache into a single point of failure for authentication.

When rebuilding flows, preserve the double binding between `registration_state` and the original OAuth `state`; `registration_state` is only for new-user registration and must not be accepted as an authenticated account-binding mechanism.

## Deployment Notes

`docker-compose.yml` defines one `api` service listening on `127.0.0.1:${API_PORT:-8080}:8080` with external `postgres` and `redis` networks. It does not build an image from this repository; provide a prebuilt image through `API_IMAGE` or tag one as `sastlink-api:current`. The health check expects:

```text
GET /health -> { "status": "ok", "db": "ok", "redis": "ok" }
```

Only PostgreSQL is a required dependency. When Redis is unreachable the endpoint still returns `200` with `{ "status": "ok", "db": "ok", "redis": "degraded" }`, because the service can serve authenticated traffic from PostgreSQL alone and restarting the container would not restore Redis. A `db` failure returns `500` with `"status": "error"`.

## CI And Security

`.github/workflows/ci.yml` runs for pull requests targeting `main` and supports manual dispatch. It has three parallel jobs:

- **lint** — golangci-lint using `.golangci.yml` against the Go module.
- **test** — `go test -race -shuffle=on -coverprofile=coverage.out -covermode=atomic ./...`; PostgreSQL integration tests provision isolated PostgreSQL 16 containers through Testcontainers and require a healthy Docker provider.
- **build** — builds both `./cmd/api` and `./cmd/migrate`.

`.github/workflows/security.yml` runs weekly (`0 3 * * 1`) or by manual dispatch and scans the Go module with version-pinned `gosec` and `govulncheck`.
