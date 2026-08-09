-- Seeds sast-people, the one third-party client permitted to call the admin API on
-- an administrator's behalf. It is created here rather than through the console
-- because adminclient refuses every admin scope outright: there is deliberately no
-- self-service path to an administrative credential, so the registration has to
-- arrive as schema.
--
-- third_party, not first_party, and that is the load-bearing choice. authorizeScopeForClient
-- short-circuits first_party with no scope check at all, so a first-party client may
-- request anything this provider supports. Only a third_party registration is pinned
-- to its scopes column by scope.ContainsAll, which is the sole mechanism that bounds
-- what this client can ask for.
--
-- grant_types omits refresh_token on purpose. The refresh grant inherits scopes
-- without narrowing, so a refresh-capable admin:write token would renew itself
-- indefinitely until its family was revoked. Restricted to authorization_code, the
-- lifetime of an administrative credential is one access-token TTL and the
-- administrator must re-authorize to get another.
--
-- client_secret holds only the sha256-v1 hash. The plaintext was generated once,
-- outside this repository, and lives in the ops tool's own configuration.
--
-- Idempotent with drift detection, following V003: re-running against a database
-- that already has this client is a no-op, but a client whose properties do not match
-- aborts the migration rather than being silently overwritten. Overwriting could
-- widen the scopes or repoint the redirect_uris of a live administrative client.
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

    SELECT id,
           client_name,
           client_type,
           client_secret,
           redirect_uris,
           grant_types,
           scopes,
           is_active
    INTO existing_client
    FROM oauth_clients
    WHERE client_id = ''sast-people''\003B

    IF FOUND THEN
        IF existing_client.client_name <> ''SAST People''
            OR existing_client.client_type <> ''third_party''::client_enum
            OR existing_client.client_secret IS DISTINCT FROM ''sha256-v1$InDPxR7aft8zZEmMD_rPsYj2502gEy1dv_sBStXlAMY''
            OR existing_client.redirect_uris <> ARRAY[''https://people.sast.fun/api/auth/link'', ''http://localhost:3001/api/auth/link'']::text[]
            OR existing_client.grant_types <> ARRAY[''authorization_code'']::text[]
            OR existing_client.scopes <> ARRAY[''openid'', ''admin:read'', ''admin:write'']::text[]
            OR existing_client.is_active IS NOT TRUE
        THEN
            RAISE EXCEPTION ''cannot apply V008: oauth_clients contains non-canonical sast-people client''\003B
        END IF\003B
        RETURN\003B
    END IF\003B

    INSERT INTO oauth_clients (
        client_id,
        client_secret,
        client_name,
        client_type,
        redirect_uris,
        grant_types,
        scopes,
        is_active
    )
    VALUES (
        ''sast-people'',
        ''sha256-v1$InDPxR7aft8zZEmMD_rPsYj2502gEy1dv_sBStXlAMY'',
        ''SAST People'',
        ''third_party'',
        ARRAY[''https://people.sast.fun/api/auth/link'', ''http://localhost:3001/api/auth/link'']::text[],
        ARRAY[''authorization_code'']::text[],
        ARRAY[''openid'', ''admin:read'', ''admin:write'']::text[],
        TRUE
    )
    RETURNING id INTO inserted_client_id\003B

    INSERT INTO v008_ops_oauth_client_ownership (client_id, client_pk)
    VALUES (''sast-people'', inserted_client_id)\003B
END\003B';
