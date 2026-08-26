#!/bin/bash
# Recreates the 1c1g all-in-one bench container. The image (sastlink-allinone:test)
# must be built first via scripts/loadmix/allinone/build.sh — it packs PostgreSQL,
# Redis, and the API in one container sharing `--cpus=1 --memory=1g`.
#
# Bench-only env: rate limits opened so the driver measures path walls, not the
# limiters; JWT_ACCESS_TOKEN_EXPIRY=60s compresses the refresh cadence;
# LOG_LEVEL=warn keeps the per-request logger out of the numbers; APP_ENV=bench
# runs gin in release mode without the migrate production gate; Redis published on
# 16379 so `loadmix setup` can read the verification codes it stores.
#
# Drop the volume (docker volume rm loadtest-pgdata) and rerun `loadmix setup`
# between measurement rounds — it accumulates refresh-token rows; warm up (~15s of
# mix traffic) after each container restart before measuring, or the first requests
# hit cold caches.
set -euo pipefail

docker rm -f sastlink-allinone >/dev/null 2>&1 || true
# Every setting is passed explicitly and the repository .env is deliberately NOT
# mounted: it would carry real SMTP/GitHub/Feishu credentials into a container
# that runs `migrate up` unconditionally and exercises the mail path. The list is
# closed — config validation names every required key, so a missing one fails here
# rather than falling back to an operator's personal .env. SMTP_USERNAME/PASSWORD
# are left unset so the mailer skips AUTH and no real mailbox is reachable.
#
# A throwaway Ed25519 key is generated per run so no private key lives in git.
docker run -d --name sastlink-allinone \
  --cpus=1 --memory=1g \
  -p 127.0.0.1:8080:8080 \
  -p 127.0.0.1:16379:6379 \
  -v loadtest-pgdata:/var/lib/postgresql/data \
  -e JWT_SECRET_KEY="$(openssl genpkey -algorithm ED25519 2>/dev/null | awk '{printf "%s\\n", $0}')" \
  -e JWT_ACTIVE_KID=bench-key-1 \
  -e JWT_ISSUER=http://127.0.0.1:8080 \
  -e JWT_AUDIENCE=sast-link \
  -e JWT_REFRESH_TOKEN_EXPIRY=720h \
  -e REFRESH_TOKEN_HMAC_SECRET=bench_only_hmac_secret_at_least_32_bytes \
  -e INTERNAL_OAUTH_CLIENT_ID=sast-link-web \
  -e OAUTH_CONSENT_URL=http://127.0.0.1:8080/consent \
  -e OAUTH_LOGIN_REDIRECTS=http://127.0.0.1:8080/callback \
  -e OAUTH_LOGIN_ERROR_REDIRECT=http://127.0.0.1:8080/login-error \
  -e HSTS_MAX_AGE=31536000 \
  -e SMTP_HOST=127.0.0.1 \
  -e SMTP_PORT=1025 \
  -e SMTP_FROM=bench@invalid.test \
  -e GOMEMLIMIT=400MiB \
  -e ARGON2_MEMORY=19456 \
  -e ARGON2_TIME=2 \
  -e ARGON2_CONCURRENCY=4 \
  -e RATE_LIMIT_LOGIN_RPM=100000 \
  -e RATE_LIMIT_REFRESH_RPM=100000 \
  -e RATE_LIMIT_TOKEN_RPM=100000 \
  -e RATE_LIMIT_SEND_EMAIL_RPM=100000 \
  -e RATE_LIMIT_SEND_EMAIL_IP_RPM=100000 \
  -e JWT_ACCESS_TOKEN_EXPIRY=60s \
  -e LOG_LEVEL=warn \
  -e APP_ENV=bench \
  -e PPROF_ENABLED=true \
  -e DB_HOST=localhost -e DB_PORT=5432 -e DB_USER=sastlink \
  -e DB_NAME=sastlink -e DB_PASSWORD=change_me -e DB_SSLMODE=disable \
  -e REDIS_HOST=localhost -e REDIS_PORT=6379 -e REDIS_PASSWORD=change_me \
  -e APP_PORT=8080 \
  sastlink-allinone:test

for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then
    echo "bench container healthy after ${i}s"
    exit 0
  fi
  sleep 1
done
echo "bench container did not become healthy" >&2
exit 1
