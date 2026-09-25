-- V018: oauth_refresh_tokens.revoked_reason records why a user-level bulk
-- revocation (role change, account close, password change/reset) cut the
-- token, so the next refresh can be audited as session_revoked instead of
-- reading as a replay. NULL keeps meaning rotation-family revocations
-- (rotate / RevokeFamily / pre-V018 rows), whose refresh outcomes are
-- unchanged. Only rows being revoked pick the reason up — an already-revoked
-- row keeps the reason of its own death, so a replay signal is never masked
-- by a later administrative revocation.

ALTER TABLE oauth_refresh_tokens ADD COLUMN revoked_reason text;
