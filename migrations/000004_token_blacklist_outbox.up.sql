CREATE TABLE token_blacklist_outbox (
    id BIGSERIAL PRIMARY KEY,
    token_id VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    next_delivery_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    last_error TEXT,
    claim_token VARCHAR(64),
    claimed_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_token_blacklist_outbox_token_id UNIQUE (token_id),
    CONSTRAINT ck_token_blacklist_outbox_attempt_count_nonnegative CHECK (attempt_count >= 0)
);

CREATE INDEX idx_token_blacklist_outbox_due
    ON token_blacklist_outbox (next_delivery_at, expires_at, id)
    WHERE claim_token IS NULL;

CREATE INDEX idx_token_blacklist_outbox_claimed_until
    ON token_blacklist_outbox (claimed_until)
    WHERE claim_token IS NOT NULL;

CREATE INDEX idx_token_blacklist_outbox_expiry
    ON token_blacklist_outbox (expires_at);
