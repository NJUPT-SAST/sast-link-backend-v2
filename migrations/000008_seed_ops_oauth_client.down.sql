DO U&'DECLARE
    owned_client RECORD\003B
BEGIN
    FOR owned_client IN
        SELECT client_id, client_pk FROM v008_ops_oauth_client_ownership
    LOOP
        DELETE FROM oauth_clients AS client
        WHERE client.id = owned_client.client_pk
          AND client.client_id = owned_client.client_id
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
    END LOOP\003B

    DROP TABLE v008_ops_oauth_client_ownership\003B
END\003B';
