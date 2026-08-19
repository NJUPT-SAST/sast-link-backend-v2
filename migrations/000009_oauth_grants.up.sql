-- oauth_grants records which applications a user has authorized via the consent
-- screen. It is long-lived by design: unlike oauth_authorizations (short-lived
-- single-use codes), these rows are the user's consent history and are never
-- swept by the retention worker. One row per user-client pair, upserted on each
-- consent and deleted when the user revokes the application or when the user or
-- client row it references is deleted (both foreign keys cascade).
CREATE TABLE oauth_grants (
    user_id    BIGINT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    client_id  BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes     TEXT[] NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, client_id)
);

-- This index serves the sub-table scan when an oauth_clients row is deleted and
-- its grants must cascade: PostgreSQL otherwise falls back to a sequential scan.
-- The list query is already covered by the primary key.
CREATE INDEX idx_oauth_grants_client_id ON oauth_grants(client_id);

-- Backfill any consent still alive in oauth_authorizations so a user who
-- authorized moments before the deploy does not see the application vanish.
-- Idempotent via ON CONFLICT DO NOTHING. Retention has already cleared anything
-- older than about an hour, so this only ever rescues the most recent consents.
INSERT INTO oauth_grants (user_id, client_id, scopes, granted_at)
SELECT DISTINCT ON (user_id, client_id) user_id, client_id, scopes, created_at
FROM oauth_authorizations
ORDER BY user_id, client_id, created_at DESC
ON CONFLICT DO NOTHING;
