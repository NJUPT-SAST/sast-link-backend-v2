DO U&'DECLARE
    owned_client_pk BIGINT\003B
BEGIN
    SELECT client_pk
    INTO owned_client_pk
    FROM v003_builtin_oauth_client_ownership
    WHERE client_id = ''sast-link-web''\003B

    IF FOUND THEN
        DELETE FROM oauth_clients AS client
        WHERE client.id = owned_client_pk
          AND client.client_id = ''sast-link-web''
          AND client.client_name = ''SAST Link Web''
          AND client.client_type = ''first_party''::client_enum
          AND client.client_secret IS NULL
          AND client.redirect_uris = ARRAY[''https://link.sast.fun/oauth/callback'', ''http://localhost:3000/oauth/callback'']::text[]
          AND client.grant_types = ARRAY[''authorization_code'', ''refresh_token'']::text[]
          AND client.scopes = ARRAY[''openid'', ''profile'', ''email'']::text[]
          AND client.is_active = TRUE
          AND NOT EXISTS (
              SELECT 1 FROM oauth_authorizations AS authz
              WHERE authz.client_id = client.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM oauth_access_tokens AS access_token
              WHERE access_token.client_id = client.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM oauth_refresh_tokens AS refresh_token
              WHERE refresh_token.client_id = client.id
          )\003B
    END IF\003B

    DROP TABLE v003_builtin_oauth_client_ownership\003B
END\003B';
