DO U&'BEGIN
    IF EXISTS (
        SELECT 1
        FROM oauth_authorizations
        WHERE code_challenge_method <> ''S256''
    ) THEN
        RAISE EXCEPTION ''cannot apply V002: oauth_authorizations contains non-S256 code_challenge_method rows''\003B
    END IF\003B
END\003B';

ALTER TABLE oauth_authorizations
    DROP CONSTRAINT ck_oauth_authorizations_challenge_method;

ALTER TABLE oauth_authorizations
    ADD CONSTRAINT ck_oauth_authorizations_challenge_method
    CHECK (code_challenge_method = 'S256');
