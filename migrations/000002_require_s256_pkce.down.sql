DO U&'BEGIN
    ALTER TABLE oauth_authorizations
        DROP CONSTRAINT ck_oauth_authorizations_challenge_method\003B

    ALTER TABLE oauth_authorizations
        ADD CONSTRAINT ck_oauth_authorizations_challenge_method
        CHECK (code_challenge_method IN (''S256'', ''plain''))\003B
END\003B';
