-- The retention worker deletes expired authorization codes regardless of is_used,
-- but idx_oauth_authorizations_expires_at is partial (WHERE is_used = FALSE), so it
-- cannot serve that scan: a redeemed code is exactly the row the partial index
-- excludes, and redeemed codes are the common case. Without this index the hourly
-- cleanup degrades to a sequential scan over the whole table.
--
-- The other three retention targets are already covered: oauth_access_tokens and
-- audit_logs have full indexes on expires_at / created_at, and
-- idx_oauth_refresh_tokens_expires_at is partial on WHERE revoked_at IS NOT NULL,
-- which is precisely the refresh-token delete condition.
CREATE INDEX idx_oauth_authorizations_expires_at_all
    ON oauth_authorizations(expires_at);
