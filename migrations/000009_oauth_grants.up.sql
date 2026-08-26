-- Consent history: one row per user-client pair, upserted on every consent and
-- deleted on revoke or when either referenced row is deleted (both foreign keys
-- cascade). Unlike the authorization codes that created them, these rows are
-- never swept by the retention worker.
CREATE TABLE oauth_grants (
    user_id    BIGINT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    client_id  BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes     TEXT[] NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, client_id)
);

-- Serves the cascade scan when an oauth_clients row is deleted. The list query
-- is already covered by the primary key.
CREATE INDEX idx_oauth_grants_client_id ON oauth_grants(client_id);

-- Backfill consent still alive in oauth_authorizations so a pre-deploy consent
-- is not lost. Idempotent via ON CONFLICT DO NOTHING, and retention already
-- cleared anything older, so only the most recent consents are rescued.
INSERT INTO oauth_grants (user_id, client_id, scopes, granted_at)
SELECT DISTINCT ON (user_id, client_id) user_id, client_id, scopes, created_at
FROM oauth_authorizations
ORDER BY user_id, client_id, created_at DESC
ON CONFLICT DO NOTHING;
