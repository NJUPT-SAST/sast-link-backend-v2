# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Status

SAST Link Backend V2 is the backend for SAST's unified identity/authentication center and personnel information system. The current implementation establishes the Go module, HTTP service skeleton, V001–V007 PostgreSQL schema migrations (including the built-in `sast-link-web` first-party client, the token-blacklist outbox, the cross-table email uniqueness triggers, V006's full expires_at index for authorization-code retention, and V007's `audit_logs.actor_client_id`). No migration seeds an integrator client: a `client_secret` needs rotation, while a seed migration needs drift detection to avoid overwriting a live registration, and the two are incompatible — once the secret is rotated the seeded hash no longer matches and every path that replays that migration aborts. Integrator clients, delegated ones included, are registered through the console, persistence entities and Auth repositories, authentication primitives, the internal session flow (password login, refresh rotation/replay handling, logout, JWT middleware, auth-state-cache invalidation through the token-blacklist outbox), the SMTP mailer, the two-step email registration flow, password change/reset with whole-user token revocation and authorization-code invalidation, third-party email binding with Bind-Tickets, self-service profile management (profile read/edit, identity listing, unbind with password confirmation, avatar upload), the OAuth 2.1 / OIDC provider (authorize/consent/token/revoke, discovery, JWKS, UserInfo, and the signed-in user's authorized-apps view), the admin console (OAuth client registry, user management, audit-log queries, console overview stats), and third-party OAuth login (GitHub and Lark authorize/callback, `login_code` exchange, authenticated binding, and the `registration_state` + `oauth_state` double-checked registration completion). PostgreSQL 16 and Redis integration tests use Testcontainers. Data-retention cleanup runs as an in-process Go worker (`internal/worker/retention.go`) coordinated across instances by a PostgreSQL advisory lock; pg_cron is deliberately not used. Avatar upload is implemented (`PUT /user/avatar`, Tencent COS via `internal/adapter/cos` + `internal/objectstore` ports, optional `STORAGE_*` group, COS content review with fail-closed semantics, old-object cleanup, per-user rate limit, `upload_avatar` audit). Device management is implemented (`GET /user/devices` + `DELETE /user/devices/:id`; device records live in Redis keyed by the token family ID — a device is exactly one internal-session token family (password/register/GitHub/Lark logins; the OAuth provider authorization-code flow for third-party apps does not register devices), so logout/change-password revocations and device cleanup stay in lockstep, evicting the oldest device past the 5-device cap revokes its family so the cap is a session limit, not just a list limit, GitHub/Lark logins register through `POST /oauth/exchange-code` in the same store, expired records resurrect on refresh within the cap, phantom members (Hash lost, member alive) never occupy a cap slot, and every session-termination path (logout, device logout, eviction, password change/reset, refresh replay/rotation failure/expiry, admin demotion/ban/account close) clears the record and writes an audit event (`logout`, `logout_device`, `evict_device`, …); PRD §6.1).

`cmd/api` connects PostgreSQL and Redis and serves health and the internal auth endpoints: `POST /user/login`, `POST /auth/refresh`, `POST /auth/register/send-code`, `POST /auth/register/verify-code`, `POST /auth/register`, `POST /auth/forgot-password/send-code`, `POST /auth/reset-password`, and — behind the scoped user gate (`RequireUserAuth` + per-route `user:read`/`user:write` scope gates, admitting the console session and any client whose token carries the scope the route names) — `POST /auth/logout`, `POST /auth/change-password`, `GET /user/profile`, `PUT /user/profile`, `GET /user/identities`, `POST /user/identities/email`, `POST /user/identities/email/verify`, `DELETE /user/identities/:id`, `GET /user/devices`, and `DELETE /user/devices/:id`.

It also serves the OAuth 2.1 / OIDC provider: `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`, `GET /oauth/authorize` (unauthenticated, rate limited per IP), `POST /oauth/token`, `POST /oauth/revoke`, `GET /userinfo` and `POST /userinfo` (any authenticated client — `/userinfo` authenticates inline via `AuthenticateAnyClient`, deliberately skipping the `azp` gate that would reject the third-party tokens it exists to serve), and — behind the JWT middleware — `POST /oauth/authorize/consent`, `GET /oauth/authorize/consent` (peeks the stashed request and returns the verified `client_name` / `scopes` / `expires_in` so the consent page renders server-verified metadata instead of the spoofable consent-URL values; rate limited per user, not per IP, because campus egress shares one NAT address), `GET /oauth/grants`, and `DELETE /oauth/grants/:client_id` (the signed-in user's authorized-apps list; the revoke cuts every token the user holds with that client and deletes the consent history, so the client must re-consent on next use). Behind delegated-aware authentication plus a scope gate plus an admin role check: `GET`/`POST /admin/oauth-clients`, `PUT /admin/oauth-clients/:id`, `PUT`/`DELETE /admin/users/:id`, `PUT /admin/users/:id/restore`, `GET /admin/audit-logs`, and `GET /admin/stats` (account / client / recent-audit aggregates for the console overview). Behind the same plus an admin-or-lecturer check (`adminhandler.ReaderRoles`): `GET /admin/users` and `GET /admin/users/:id`.

The `/admin` group is the admin surface — one of two scoped surfaces a registered token may reach, the other being `/user` below — admitting the built-in console client and any third-party client whose token carries an admin scope. It authenticates through `Authenticator.RequireAdminAuth` rather than `RequireAuth`, which admits the built-in console client and any third-party client whose token carries an admin scope. There is no hardcoded delegate: the registration's `scopes` column IS the delegation marker, because `scope.ContainsAll` pins every client's requestable scopes to it and `checkScopeForClient` additionally refuses admin scopes for `first_party` clients outright, since a public client's token request is authenticated by PKCE alone. Granting delegation is therefore a console action (`POST`/`PUT /admin/oauth-clients`), guarded by `adminclient.checkCapabilityScopeGrant` on both doors: third_party only, console actor only, and not in the same request as a `redirect_uris` rewrite — the refresh grant is permitted, because the /admin role gate reads the subject's role from the database on every request, so refreshing an admin-scoped token never widens who may use it — all decided on the merged post-request state so splitting a change in two cannot bypass them. Narrowing a client's scopes or newly granting an admin scope revokes that client's live tokens, and the consent and code-redemption legs re-check scopes against the live registration, so a revocation takes effect at once instead of one TTL later. Routes are mounted through `adminhandler.Gates`, a struct rather than positional middleware, and `RegisterRoutes` panics if any gate is nil — a route cannot lose a permission by omission. Each route names both a scope gate (`adminhandler.ReadScopes` accepts `admin:read` or `admin:write`; `WriteScopes` requires `admin:write`) and a role gate. The two are independent and both required: the role gate answers "is this user allowed" (read from the DB row, so a demotion lands on the next request), the scope gate answers "was this credential granted the right to act" and only constrains delegated tokens — internal console tokens are exempt from it, since they carry only the three session scopes.

The `/user` group is the self-service surface, reached by any token carrying a user scope (the console session is exempt). It authenticates through `Authenticator.RequireUserAuth`, which admits the built-in console token and any other token carrying a user scope. The user scopes carry no client-type constraint: every `/user` endpoint operates on the token subject's own record, so an application holding them is never a look-up-anyone credential. `sessionhandler.ReadScopes` (`user:read` or `user:write`) gates the read endpoints (`GET /user/profile`, `GET /user/identities`, `GET /user/devices`); `WriteScopes` (`user:write`) gates the write endpoints (`PUT /user/profile`, `PUT /user/avatar`, the identity-binding routes, `POST /auth/change-password`, `POST /auth/logout`, `DELETE /user/devices/:id`). Write implies read, and the console token is exempt from both scope gates. Granting a user scope is a console action guarded by the same `adminclient.checkCapabilityScopeGrant`: console actor only, and not in the same request as a `redirect_uris` rewrite; refresh is permitted. Newly granting or narrowing a user scope revokes the client's live tokens, same as an admin scope. `Authenticate`/`requireInternalClient` are untouched, so every route that does not opt into the user or admin gate still rejects third-party tokens outright.

It serves the third-party OAuth login flow (SAST Link as an OAuth *client*, the opposite direction from the provider endpoints above): `GET /oauth/github`, `GET /oauth/github/callback`, `GET /oauth/lark`, `GET /oauth/lark/callback`, `POST /oauth/exchange-code`, and — behind the JWT middleware — `POST /user/identities/github` and `POST /user/identities/lark`. Each provider is gated by its own `OAUTH_GITHUB_ENABLED` / `OAUTH_FEISHU_ENABLED` flag; a disabled provider's routes stay registered and answer `40000` rather than 404, so the contract does not change with configuration.

`docs/openapi.yaml` is the target contract rather than an inventory: every path is now registered. The admin console's implementation deliberately tightens the contract in four places — see the status note at the top of `docs/API文档.md` §6: `PUT /admin/users/:id` refuses `state: is_deleted` (422), `email_type` is only accepted alongside a matching `login_email` (400), `page_size` is capped at 100 everywhere (and `page` at 2^30, since the offset multiplication overflows), and `keyword` is capped at 255.

It never performs DDL or schema migrations at startup. `cmd/migrate` is the only command that inspects or changes schema migration state.

## Current Commands

The project targets Go `1.26.5`, Gin, GORM, PostgreSQL 16+, Redis 8+, and testcontainers-go. Full integration tests provision PostgreSQL 16 through Testcontainers and require Docker.

```powershell
# Download modules
go mod download

# Run all tests with race detection, randomized execution order, and coverage.
# Quote the -flag=value arguments: PowerShell splits an unquoted -a=b at the "=",
# so go test receives ".out" as a package path and fails with
# "no required module provides package .out" before running anything. The same
# applies to `go tool cover "-func=coverage.out"`.
go test -race -shuffle=on "-coverprofile=coverage.out" "-covermode=atomic" ./...

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

`docker-compose.yml` is self-contained for local development: it provisions its own PostgreSQL and Redis, builds the image from the repository `Dockerfile`, runs `migrate up` as a one-shot service, and only then starts the API. Set `API_IMAGE` to point at a prebuilt image instead. The published host ports are deliberately offset (`15432`, `16379`) so the stack does not collide with a PostgreSQL or Redis already running on the machine.

## Source Of Truth Documents

- `README.md`: current implementation inventory and entry points.
- `docs/SAST Link v2 PRD.md`: product and architecture source of truth, including implementation tracking.
- `docs/API文档.md`: human-readable API contract, response envelopes, business error codes, and endpoint behavior.
- `docs/openapi.yaml`: machine-readable OpenAPI 3.0.1 contract. Keep it aligned with `docs/API文档.md` when endpoints change.
- `docs/psql-db-design.md`: PostgreSQL schema design, enum values, indexes, triggers, token-family cascade revocation flow, and the retention-worker cleanup policy (including why pg_cron is not used).
- `docs/runbooks/database-baseline.md`: V001 baseline procedure for the pre-existing production schema.
- `docs/runbooks/caddy-reverse-proxy.md`: Caddy routing for the externally visible `/v2` prefix. Every route in this service is registered at the root — there is no `/v2` in the Go code — so the proxy strips it with `handle_path`. It also carries the third-party OAuth callback layout: the bind page must sit under the same `/v2/oauth` prefix as the login callback so one GitHub OAuth App registration covers both.
- `migrations/`: embedded versioned SQL migrations, including V002's S256-only PKCE constraint. The runner splits statements on semicolons and does not understand SQL comments, so a semicolon inside a comment truncates the file and the remainder is parsed as SQL; V001/V005 escape semicolons inside function bodies as `\003B` within `U&'...'` literals, and a comment simply must not contain one. V003 is the only client seed: idempotent, drift-detecting (a non-canonical existing row aborts the migration rather than being overwritten), and recording what it created in an ownership table so `down` deletes only its own unreferenced row. Its `client_secret` is NULL, so it is not subject to the rotation problem that keeps integrator clients out of migrations.
- `.env.example`: environment variable names and defaults expected by the service.
- `docker-compose.yml` and `Dockerfile`: a self-contained local stack (PostgreSQL, Redis, one-shot migration, API) and the multi-stage build behind it.
- `scripts/local-oauth-complete-flow.sh`: drives the whole OAuth surface against a locally running API. Its container names and ports default to the compose stack; the third-party legs need manual browser authorization.
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
- Operations: health check, structured JSON logs, PostgreSQL data retention via an in-process ticker worker, and Redis-backed rate limiting/session helpers.

Important design constraints:

- Standard non-OAuth endpoints use `{ "code": 0, "message": "ok", "data": ... }` response envelopes.
- OAuth `/oauth/authorize`, `/oauth/token`, and `/oauth/revoke` follow RFC 6749 formats instead of the standard envelope.
- OIDC UserInfo errors follow RFC 6750-style `invalid_token` responses.
- The public display-card endpoint `GET /card/:id` is currently not served: its sequential numeric IDs made the member list enumerable, and the privacy redesign is pending. The OIDC `profile` URL claim was removed together with the card, so no claim or example points at a card URL.
- Access tokens are EdDSA (Ed25519) JWTs with `kid`, `jti`, `sub`, `role`, `state`, `token_version`, and the canonical OAuth/OIDC `scope` claim; supported scopes are `openid`, `profile`, `email`, `admin:read`, `admin:write`, `user:read`, and `user:write`, with `openid` required and canonicalized before signing or persistence. The `profile` scope additionally carries `role`, this service's own claim rather than an OIDC one, read from the database row at signing time (never from the requesting token's own role claim, which is a snapshot that survives a demotion) and documented as a display hint rather than an authorization input. The four capability scopes grant no OIDC claim — `scope.ClaimScopes` filters every non-OIDC scope out before the ID Token signer and `/userinfo` map scopes to claims, so `openid admin:read` and `openid user:read` each yield exactly what `openid` alone yields. The two admin scopes may only be granted to a `third_party` client: `checkScopeForClient` refuses them for `first_party` clients whatever the registration says, because a first-party client is public, so the token endpoint authenticates it by PKCE alone and an intercepted authorization code is one barrier (exact-match `redirect_uri`) short of an administrative token, where a confidential client has two. The two user scopes carry no client-type constraint: they reach the self-service `/user` surface, whose every endpoint operates on the token subject's own record, so an application holding them is never a look-up-anyone credential — the subject is pinned by the token, whatever client it was issued to. Every client type, first-party included, is pinned to its registration by `scope.ContainsAll` — the first-party exemption that made that column advisory was removed, since it was retroactive: any newly supported scope would have been granted to every existing first-party registration with no grant action or audit row. JWKS exposes public keys (`kty` OKP, `crv` Ed25519).
- Refresh tokens are opaque strings stored as HMAC-SHA256 hashes and rotated by `family_id` + `sequence`.
- Authorization code replay or refresh-token replay should revoke the whole token family across access and refresh metadata. A 30s grace window (`RefreshGracePeriod`) exempts the first refresh after a rotation: two tabs that raced get to keep the winner's session. Trade-off: a stolen-token owner who presents their already-rotated token within that 30s window does not cut the attacker's family — the theft window is bounded by the grace value and documented as accepted.
- Password hashing is **argon2id-only** (default m=19456 KiB / t=2, the OWASP low-memory floor adopted for the 1c1g target). Legacy `pbkdf2-sha512-v1` hashes from before the switch verify read-only; a successful login rehashes them to argon2id in place (`PasswordHasher.ShouldRehash`), which is the only way a KDF change reaches existing accounts.
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
- `audit_logs`: auth/admin audit trail retained for 90 days. V007 adds `actor_client_id`, the OAuth client that *performed* the action (the actor, not the subject — that is `resource_id`). NULL is a meaningful value: no OAuth credential authorized the action (unauthenticated flows, workers, pre-V007 rows). It is populated on the five admin actions and on `oauth_authorize`/`oauth_token`/`oauth_revoke`; a console action records the built-in client id explicitly rather than NULL, which is what keeps NULL unambiguous. Nullable with no FK, so an audit row outlives the registration it names.

The user state machine is `njupter -> on_sast -> retired_sast`; any non-deleted state can move to `is_deleted`, and restore returns to `njupter`.

## Redis Design Anchors

Redis is used for short-lived and operational state, not durable source-of-truth data. The PRD defines keys for verification codes, rate limits, devices, auth-state cache, OAuth state, registration state, login codes, login failures, Register-Tickets, and Bind-Tickets. Most flows require one-time consumption via GetDel semantics. `token_version` is deliberately not cached in Redis: the auth middleware already reads it from the same DB query that fetches access-token revocation state.

Every Redis-backed check must declare its behavior when Redis is unavailable, following one of two classes:

- **Fail-closed (Redis is the only store)**: verification codes, OAuth `state`, `registration_state`, `login_code`, Register/Bind-Tickets, and idempotency keys. A missing value cannot be treated as valid, so the flow must be rejected and restarted by the user.
- **Fail-open (PostgreSQL is authoritative, or loss only widens a rate window)**: the auth-state cache, login-failure counters/lockout, endpoint rate limits, and device records. These log at WARN and continue. The auth-state cache is safe to skip because the middleware falls back to the authoritative `oauth_access_tokens.revoked_at` DB check on a cache miss or error — the cache only shortens the common hit path. Revocation paths write a short-lived tombstone (not a plain delete) and the cache fill uses SET NX, so a request that read the DB just before a revoking transaction commits cannot re-seed a stale pre-revocation blob after the revocation — the write-race window is closed, not just bounded by the TTL.

  Device records (PRD §6.1) are the one exception to "Redis is the only store ⇒ fail-closed". They are Redis-only operational state: a session's validity lives in `oauth_refresh_tokens` / `oauth_access_tokens`, and every device-killing path revokes there in a transaction before touching the record, so an outage costs the user the device *view* (an empty list) and temporarily under-enforces the 5-device cap — never the ability to log in or log out. The one device check that gates a destructive action, `DeviceOwnedBy` ("logout this specific device"), fails closed: an unreadable set proves nothing and must not authorize a family revoke.

Do not make a fail-open dependency return `ErrInternal`; that turns an optional cache into a single point of failure for authentication.

When rebuilding flows, preserve the double binding between `registration_state` and the original OAuth `state`; `registration_state` is only for new-user registration and must not be accepted as an authenticated account-binding mechanism. `session.Register` enforces this: it consumes the parked identity and compares the stored `oauth_state` against the submitted one, rejecting a mismatch. An existing account gains a binding only through `POST /user/identities/*`, which identifies the caller from their Bearer token and never reads either state.

The `registration_state` key is written by `oauthloginredis.RegistrationStateStore` and read back by `sessionredis.OAuthRegistrationStore` through two separate payload structs, because neither service package may import the other. The JSON field tags are the only thing keeping them compatible — renaming one side's tag silently breaks OAuth registration, and `TestRegistrationStateIsReadableBySessionService` is what catches it.

The provider callback must never return tokens: it is a 302 to the frontend, so a token in the query string would land in browser history and `Referer` headers. It issues a one-time `login_code` that `POST /oauth/exchange-code` redeems instead. Callback redirects are validated against an exact-match allow-list (`OAUTH_LOGIN_REDIRECTS`); a prefix rule would admit `https://link.sast.fun.evil.test` and hand it a live login code.

## Deployment Notes

`docker-compose.yml` brings up `postgres`, `redis`, a one-shot `migrate`, and the `api` service on `127.0.0.1:${API_PORT:-8080}:8080`. `api` waits for both stores to report healthy and for `migrate` to exit successfully, so a schema change lands before the service that depends on it starts. The image is built from the repository `Dockerfile` (a multi-stage build producing both binaries, running as an unprivileged user), or supplied prebuilt through `API_IMAGE`. The health check expects:

```text
GET /health -> { "status": "ok", "db": "ok", "redis": "ok" }
```

Only PostgreSQL is a required dependency. When Redis is unreachable the endpoint still returns `200` with `{ "status": "ok", "db": "ok", "redis": "degraded" }`, because the service can serve authenticated traffic from PostgreSQL alone and restarting the container would not restore Redis. A `db` failure returns `500` with `"status": "error"`.

## CI And Security

`.github/workflows/ci.yml` runs for pull requests targeting `main` and supports manual dispatch. It has three parallel jobs:

- **lint** — golangci-lint using `.golangci.yml` against the Go module.
- **test** — `go test -race -shuffle=on -coverprofile=coverage.out -covermode=atomic ./...` (CI runs bash, where the quoting caveat above does not apply); PostgreSQL integration tests provision isolated PostgreSQL 16 containers through Testcontainers and require a healthy Docker provider.
- **build** — builds both `./cmd/api` and `./cmd/migrate`.

`.github/workflows/security.yml` runs weekly (`0 3 * * 1`) or by manual dispatch and scans the Go module with version-pinned `gosec` and `govulncheck`.
