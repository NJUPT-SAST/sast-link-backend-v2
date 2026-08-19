-- DeleteRevokedRefreshTokens sweeps two shapes (internal/repository/retention.go)
--   - rotated-away rows (revoked_at IS NOT NULL and sequence > 0), served by
--     idx_oauth_refresh_tokens_expires_at (partial, WHERE revoked_at IS NOT NULL)
--   - rows of an entirely dead family, including the never-rotated sequence-0
--     origin rows, which have revoked_at IS NULL
-- The second shape has no index on the outer expires_at predicate: the partial
-- index excludes exactly those rows, so the sweep degraded to a sequential scan
-- over the whole table plus a per-row NOT EXISTS. V006's comment said the
-- partial index is precisely the refresh-token delete condition. That was true
-- when retention deleted only revoked rows, and it is stale since the
-- dead-family branch was added. This migration supplies the missing index.
-- NOTE: no semicolons inside comments — the migration runner splits on them.
CREATE INDEX idx_oauth_refresh_tokens_expires_at_live
    ON oauth_refresh_tokens (expires_at)
    WHERE revoked_at IS NULL;
