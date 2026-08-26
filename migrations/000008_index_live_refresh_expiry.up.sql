-- DeleteRevokedRefreshTokens (internal/repository/retention.go) also sweeps
-- dead-family rows with revoked_at IS NULL, which the V006 partial index
-- (WHERE revoked_at IS NOT NULL) does not cover. This index serves that scan.
-- NOTE: no semicolons inside comments - the migration runner splits on them.
CREATE INDEX idx_oauth_refresh_tokens_expires_at_live
    ON oauth_refresh_tokens (expires_at)
    WHERE revoked_at IS NULL;
