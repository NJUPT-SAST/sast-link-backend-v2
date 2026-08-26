#!/bin/bash
# Bench-only entrypoint: packs PostgreSQL + Redis + the API into one --cpus=1
# --memory=1g container for a dedicated throwaway volume. NEVER point it at real
# infrastructure: `migrate up` applies schema changes unconditionally and Redis
# listens on all interfaces.
set -euo pipefail

export PGDATA="${PGDATA:-/var/lib/postgresql/data}"
DBUSER="${DB_USER:-sastlink}"
DBNAME="${DB_NAME:-sastlink}"
if [ -z "${REDIS_PASSWORD:-}" ]; then
  echo "REDIS_PASSWORD is required (this bench Redis listens on all interfaces)" >&2
  exit 1
fi

# Initialize the PostgreSQL data directory on first boot.
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  mkdir -p "$PGDATA"
  chown -R postgres:postgres "$PGDATA"
  su postgres -c "initdb -D '$PGDATA' -U '$DBUSER' --auth=trust"
fi

# Start PostgreSQL on localhost:5432, tuned for the 1c1g box. synchronous_commit
# stays on — these commits are the durability-critical path (on one core the fsync
# is I/O wait that overlaps with other requests).
su postgres -c "pg_ctl -D '$PGDATA' -o '-p 5432 -c listen_addresses=localhost -c max_connections=50 -c shared_buffers=256MB -c effective_cache_size=512MB' -l '$PGDATA/pg.log' start"
until su postgres -c "pg_isready -p 5432" >/dev/null 2>&1; do sleep 1; done

# The application database (initdb only creates the default one).
su postgres -c "createdb -U '$DBUSER' '$DBNAME'" 2>/dev/null || true

# Ephemeral Redis, no persistence, password required (checked above). Bind 0.0.0.0
# so the published 127.0.0.1:16379 reaches it for the loadmix setup driver; the
# loopback-only publish is what keeps the open bind safe.
redis-server --daemonize yes --port 6379 --bind 0.0.0.0 --requirepass "$REDIS_PASSWORD" --save "" --appendonly no

# Apply schema migrations.
migrate up

# Serve. Every setting arrives as an explicit -e from run-bench.sh (no .env is
# mounted); config validation fails startup if any required key is missing.
cd /app
exec api
