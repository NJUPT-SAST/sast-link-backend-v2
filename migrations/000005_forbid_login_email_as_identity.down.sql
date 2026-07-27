DROP TRIGGER trg_user_login_email_not_identity ON "user";
DROP FUNCTION forbid_identity_as_login_email();
DROP TRIGGER trg_identities_provider_id_not_login_email ON identities;
DROP FUNCTION forbid_login_email_as_identity();
