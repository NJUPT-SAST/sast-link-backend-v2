#!/bin/bash
# Recreates the 1c1g all-in-one bench container. The image (sastlink-allinone:test)
# must be built first via scripts/loadmix/allinone/build.sh — it packs PostgreSQL,
# Redis, and the API in one container sharing `--cpus=1 --memory=1g`.
#
# Bench-only env: rate limits opened so the driver measures the path walls rather
# than the limiters (the NAT-limiter finding is measured separately by rerunning
# at production values); JWT_ACCESS_TOKEN_EXPIRY=60s compresses the refresh
# cadence to ~one rotation per session-minute; LOG_LEVEL=warn keeps the per-request
# logger from distorting the numbers; APP_ENV=bench runs gin in release mode
# without triggering the migrate --confirm-production gate; Redis is published on
# 16379 so `loadmix setup` can read the verification codes it stores.
#
# The volume accumulates refresh-token rows across runs and degrades measurements
# over time; drop the volume (docker volume rm loadtest-pgdata) and rerun `loadmix
# setup` for a clean baseline. Always warm up (~15s of mix traffic) after a
# container restart before measuring, or the first requests hit cold caches and
# stall.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

docker rm -f sastlink-allinone >/dev/null 2>&1 || true
# A throwaway Ed25519 key is generated per run so no private key lives in git;
# the bench measures throughput, and signing cost is key-value independent.
docker run -d --name sastlink-allinone \
  --cpus=1 --memory=1g \
  -p 127.0.0.1:8080:8080 \
  -p 127.0.0.1:16379:6379 \
  -v "$REPO_ROOT/.env:/app/.env:ro" \
  -v loadtest-pgdata:/var/lib/postgresql/data \
  -e JWT_SECRET_KEY="$(openssl genpkey -algorithm ED25519 2>/dev/null | awk '{printf "%s\\n", $0}')" \
  -e GOMEMLIMIT=400MiB \
  -e PASSWORD_HASH_ALGORITHM=argon2id \
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
