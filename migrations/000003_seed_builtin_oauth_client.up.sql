DO U&'DECLARE
    existing_client RECORD\003B
BEGIN
    SELECT id, client_type, client_secret
    INTO existing_client
    FROM oauth_clients
    WHERE client_id = ''sast-link-web''\003B

    IF FOUND AND (
        existing_client.client_type <> ''first_party''::client_enum
        OR existing_client.client_secret IS NOT NULL
    ) THEN
        RAISE EXCEPTION ''cannot apply V003: oauth_clients contains incompatible sast-link-web client''\003B
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
    ON CONFLICT (client_id) DO UPDATE
    SET client_secret = NULL,
        client_name = EXCLUDED.client_name,
        client_type = EXCLUDED.client_type,
        redirect_uris = EXCLUDED.redirect_uris,
        grant_types = EXCLUDED.grant_types,
        scopes = EXCLUDED.scopes,
        is_active = EXCLUDED.is_active\003B
END\003B';
