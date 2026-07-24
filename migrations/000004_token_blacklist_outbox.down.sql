DO U&'BEGIN
    IF EXISTS (
        SELECT 1
        FROM token_blacklist_outbox
        WHERE expires_at > CURRENT_TIMESTAMP
    ) THEN
        RAISE EXCEPTION ''cannot revert V004: token blacklist outbox contains unexpired deliveries''\003B
    END IF\003B
END\003B';

DROP TABLE token_blacklist_outbox;
