DO U&'DECLARE
    owned_client_pk BIGINT\003B
BEGIN
    SELECT client_pk
    INTO owned_client_pk
    FROM v008_ops_oauth_client_ownership
    WHERE client_id = ''sast-people''\003B

    IF FOUND THEN
        DELETE FROM oauth_clients AS client
        WHERE client.id = owned_client_pk
          AND client.client_id = ''sast-people''
          AND client.client_name = ''SAST People''
          AND client.client_type = ''third_party''::client_enum
          AND client.client_secret = ''sha256-v1$InDPxR7aft8zZEmMD_rPsYj2502gEy1dv_sBStXlAMY''
          AND client.redirect_uris = ARRAY[''https://people.sast.fun/api/auth/link'', ''http://localhost:3001/api/auth/link'']::text[]
          AND client.grant_types = ARRAY[''authorization_code'']::text[]
          AND client.scopes = ARRAY[''openid'', ''admin:read'', ''admin:write'']::text[]
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

    DROP TABLE v008_ops_oauth_client_ownership\003B
END\003B';
