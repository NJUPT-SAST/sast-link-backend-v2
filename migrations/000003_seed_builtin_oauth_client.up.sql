DO U&'DECLARE
    existing_client RECORD\003B
    inserted_client_id BIGINT\003B
BEGIN
    CREATE TABLE v003_builtin_oauth_client_ownership (
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
    WHERE client_id = ''sast-link-web''\003B

    IF FOUND THEN
        IF existing_client.client_name <> ''SAST Link Web''
            OR existing_client.client_type <> ''first_party''::client_enum
            OR existing_client.client_secret IS NOT NULL
            OR existing_client.redirect_uris <> ARRAY[''https://link.sast.fun/oauth/callback'', ''http://localhost:3000/oauth/callback'']::text[]
            OR existing_client.grant_types <> ARRAY[''authorization_code'', ''refresh_token'']::text[]
            OR existing_client.scopes <> ARRAY[''openid'', ''profile'', ''email'']::text[]
            OR existing_client.is_active IS NOT TRUE
        THEN
            RAISE EXCEPTION ''cannot apply V003: oauth_clients contains non-canonical sast-link-web client''\003B
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
        ''sast-link-web'',
        NULL,
        ''SAST Link Web'',
        ''first_party'',
        ARRAY[''https://link.sast.fun/oauth/callback'', ''http://localhost:3000/oauth/callback'']::text[],
        ARRAY[''authorization_code'', ''refresh_token'']::text[],
        ARRAY[''openid'', ''profile'', ''email'']::text[],
        TRUE
    )
    RETURNING id INTO inserted_client_id\003B

    INSERT INTO v003_builtin_oauth_client_ownership (client_id, client_pk)
    VALUES (''sast-link-web'', inserted_client_id)\003B
END\003B';
