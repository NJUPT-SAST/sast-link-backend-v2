-- Seeds the two clients SAST People authenticates through. They arrived as schema
-- because adminclient refused every admin scope outright when this migration was
-- written. The console can now grant delegated administration under the guards in
-- adminclient.checkAdminScopeGrant, so an equivalent registration no longer needs a
-- migration. These rows stay because production already has them.
--
-- Two registrations rather than one, because the two credentials have different
-- lifetimes and different blast radii:
--
--   sast-people-admin   openid admin:read admin:write, authorization_code only.
--                       Reaches /admin/* on an administrator behalf. No refresh
--                       grant: the refresh flow inherits scopes without narrowing,
--                       so a refreshable admin:write token would renew itself
--                       indefinitely until its family was revoked. Bounded to a
--                       single access-token TTL, after which the administrator
--                       re-authorizes.
--
--   sast-people-session openid profile email, authorization_code + refresh_token.
--                       The ordinary sign-in session. It reads the signed-in user
--                       through /userinfo (the one endpoint that serves third-party
--                       tokens) and may keep itself alive, because nothing it holds
--                       grants administrative access.
--
-- Splitting them is what lets the session stay long-lived while administrative
-- capability expires promptly. Neither can do the other job: the session client holds
-- no admin scope so RequireAdminAuth rejects it, and the admin client holds no
-- profile/email scope so /userinfo tells it only who the subject is.
--
-- Neither client is special-cased anywhere in the code. Delegated administration is
-- whatever registration carries an admin scope, and the console can grant it, so these
-- two rows are ordinary registrations that happen to arrive as schema.
--
-- The admin half being third_party is load-bearing rather than incidental. A
-- first_party client is public — the token endpoint authenticates it by PKCE alone —
-- so checkScopeForClient refuses the admin scopes for it outright, whatever its
-- registration says. Only a confidential client may hold delegated administration.
--
-- Both share the same redirect_uris. authorize validates that the URI appears in the
-- registration of the client being used, not that it is globally unique, so People
-- serves both legs from one callback endpoint.
--
-- client_secret holds only the sha256-v1 hash. Each plaintext was generated once,
-- outside this repository, and lives in the integrator own configuration.
--
-- Idempotent with drift detection, following V003: re-running against a database that
-- already has these clients is a no-op, but a client whose properties do not match
-- aborts the migration rather than being silently overwritten. Overwriting could widen
-- the scopes or repoint the redirect_uris of a live administrative client.
--
-- The runner splits statements on semicolons and does not understand SQL comments, so
-- the body below escapes its own semicolons as \003B inside a U&'...' literal, and no
-- comment above this line may contain one.
DO U&'DECLARE
    existing_client RECORD\003B
    inserted_client_id BIGINT\003B
BEGIN
    CREATE TABLE v008_ops_oauth_client_ownership (
        client_id VARCHAR(255) PRIMARY KEY,
        client_pk BIGINT NOT NULL
    )\003B

    SELECT id, client_name, client_type, client_secret, redirect_uris, grant_types, scopes, is_active
    INTO existing_client
    FROM oauth_clients
    WHERE client_id = ''sast-people-admin''\003B

    IF FOUND THEN
        IF existing_client.client_name <> ''SAST People 管理''
            OR existing_client.client_type <> ''third_party''::client_enum
            OR existing_client.client_secret IS DISTINCT FROM ''sha256-v1$bn98ZFG7xkkc9tvrhR1pLJcFAQz-b_-QL7-rWTvSEdc''
            OR existing_client.redirect_uris <> ARRAY[''https://people.sast.fun/api/auth/link'', ''http://localhost:3001/api/auth/link'']::text[]
            OR existing_client.grant_types <> ARRAY[''authorization_code'']::text[]
            OR existing_client.scopes <> ARRAY[''openid'', ''admin:read'', ''admin:write'']::text[]
            OR existing_client.is_active IS NOT TRUE
        THEN
            RAISE EXCEPTION ''cannot apply V008: oauth_clients contains non-canonical sast-people-admin client''\003B
        END IF\003B
    ELSE
        INSERT INTO oauth_clients (
            client_id, client_secret, client_name, client_type,
            redirect_uris, grant_types, scopes, is_active
        )
        VALUES (
            ''sast-people-admin'',
            ''sha256-v1$bn98ZFG7xkkc9tvrhR1pLJcFAQz-b_-QL7-rWTvSEdc'',
            ''SAST People 管理'',
            ''third_party'',
            ARRAY[''https://people.sast.fun/api/auth/link'', ''http://localhost:3001/api/auth/link'']::text[],
            ARRAY[''authorization_code'']::text[],
            ARRAY[''openid'', ''admin:read'', ''admin:write'']::text[],
            TRUE
        )
        RETURNING id INTO inserted_client_id\003B

        INSERT INTO v008_ops_oauth_client_ownership (client_id, client_pk)
        VALUES (''sast-people-admin'', inserted_client_id)\003B
    END IF\003B

    SELECT id, client_name, client_type, client_secret, redirect_uris, grant_types, scopes, is_active
    INTO existing_client
    FROM oauth_clients
    WHERE client_id = ''sast-people-session''\003B

    IF FOUND THEN
        IF existing_client.client_name <> ''SAST People''
            OR existing_client.client_type <> ''third_party''::client_enum
            OR existing_client.client_secret IS DISTINCT FROM ''sha256-v1$xJsIFVFVfwXsV3A1exqk_xJWgL8KfF_pHYvqe4Xi7z0''
            OR existing_client.redirect_uris <> ARRAY[''https://people.sast.fun/api/auth/link'', ''http://localhost:3001/api/auth/link'']::text[]
            OR existing_client.grant_types <> ARRAY[''authorization_code'', ''refresh_token'']::text[]
            OR existing_client.scopes <> ARRAY[''openid'', ''profile'', ''email'']::text[]
            OR existing_client.is_active IS NOT TRUE
        THEN
            RAISE EXCEPTION ''cannot apply V008: oauth_clients contains non-canonical sast-people-session client''\003B
        END IF\003B
        RETURN\003B
    END IF\003B

    INSERT INTO oauth_clients (
        client_id, client_secret, client_name, client_type,
        redirect_uris, grant_types, scopes, is_active
    )
    VALUES (
        ''sast-people-session'',
        ''sha256-v1$xJsIFVFVfwXsV3A1exqk_xJWgL8KfF_pHYvqe4Xi7z0'',
        ''SAST People'',
        ''third_party'',
        ARRAY[''https://people.sast.fun/api/auth/link'', ''http://localhost:3001/api/auth/link'']::text[],
        ARRAY[''authorization_code'', ''refresh_token'']::text[],
        ARRAY[''openid'', ''profile'', ''email'']::text[],
        TRUE
    )
    RETURNING id INTO inserted_client_id\003B

    INSERT INTO v008_ops_oauth_client_ownership (client_id, client_pk)
    VALUES (''sast-people-session'', inserted_client_id)\003B
END\003B';
