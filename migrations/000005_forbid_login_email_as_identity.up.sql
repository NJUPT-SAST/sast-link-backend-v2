-- A login email must never also be bound as an other_mail identity, or login
-- ownership becomes ambiguous. Cross-table uniqueness cannot be expressed as a
-- UNIQUE constraint, so triggers on both sides enforce it, serializing on an
-- advisory key derived from the address, because a plain BEFORE-row trigger can
-- let two concurrent inserts slip past.
--
-- Semicolons inside the function bodies below are escaped as \003B because the
-- migration runner splits statements on semicolons (V001 convention).

DO U&'BEGIN
    IF EXISTS (
        SELECT 1
        FROM "user" u
        JOIN identities i
          ON i.provider = ''other_mail''
         AND i.provider_id = u.login_email
    ) THEN
        RAISE EXCEPTION ''cannot install cross-table email invariant: existing conflicts found''
            USING ERRCODE = ''check_violation''\003B
    END IF\003B
END';

CREATE FUNCTION forbid_login_email_as_identity() RETURNS trigger
LANGUAGE plpgsql AS U&'BEGIN
    IF NEW.provider <> ''other_mail'' THEN
        RETURN NEW\003B
    END IF\003B
    PERFORM pg_advisory_xact_lock(hashtextextended(LOWER(NEW.provider_id), 0))\003B
    IF EXISTS (SELECT 1 FROM "user" WHERE login_email = NEW.provider_id) THEN
        RAISE EXCEPTION ''email % is already a login email'', NEW.provider_id
            USING ERRCODE = ''unique_violation'',
                  CONSTRAINT = ''ck_identities_provider_id_not_login_email''\003B
    END IF\003B
    RETURN NEW\003B
END\003B';

CREATE TRIGGER trg_identities_provider_id_not_login_email
    BEFORE INSERT OR UPDATE OF provider, provider_id ON identities
    FOR EACH ROW EXECUTE FUNCTION forbid_login_email_as_identity();

CREATE FUNCTION forbid_identity_as_login_email() RETURNS trigger
LANGUAGE plpgsql AS U&'BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(LOWER(NEW.login_email), 0))\003B
    IF EXISTS (
        SELECT 1 FROM identities
        WHERE provider = ''other_mail'' AND provider_id = NEW.login_email
    ) THEN
        RAISE EXCEPTION ''email % is already bound as an identity'', NEW.login_email
            USING ERRCODE = ''unique_violation'',
                  CONSTRAINT = ''ck_user_login_email_not_identity''\003B
    END IF\003B
    RETURN NEW\003B
END\003B';

CREATE TRIGGER trg_user_login_email_not_identity
    BEFORE INSERT OR UPDATE OF login_email ON "user"
    FOR EACH ROW EXECUTE FUNCTION forbid_identity_as_login_email();
