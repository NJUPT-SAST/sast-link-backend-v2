-- A user's primary login email must never appear as an other_mail identity.
-- The service checks this before inserting, but login_email and
-- identities.provider_id are unique only within their own table, so two
-- concurrent transactions (a registration and a bind of the same address) can
-- both pass their pre-flight check and both commit, leaving one address in both
-- tables. FindByLoginIdentifier resolves accounts by email, so that state makes
-- login ownership ambiguous.
--
-- Cross-table uniqueness cannot be expressed as a UNIQUE constraint, so enforce
-- it with triggers on both sides. Note that BEFORE-row triggers read committed
-- data, so a pair of concurrent inserts can still slip past: SELECT ... FOR
-- UPDATE on the counterpart row is not possible when that row does not exist
-- yet. The gap is closed by locking a deterministic advisory key derived from
-- the address, which serializes any two transactions touching the same email.
--
-- Semicolons are escaped as \003B inside the unicode string literals below
-- because the migration runner splits statements on semicolons, matching the
-- convention established in V001.

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
