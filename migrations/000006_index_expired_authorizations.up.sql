-- The retention worker deletes expired authorization codes whether used or not,
-- and idx_oauth_authorizations_expires_at only covers unused codes, so this full
-- index is what the sweep scans. The other retention targets already have a
-- covering index.
CREATE INDEX idx_oauth_authorizations_expires_at_all
    ON oauth_authorizations(expires_at);
