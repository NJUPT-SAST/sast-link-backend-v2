-- Flag accounts whose required "user" columns still carry migration debris
-- (blank fields, or a name filled in with the student ID), so the frontend can
-- route them to a completion page. Pure legacy state: the current input layer
-- rejects both shapes.
--
-- Soft signal only: no request is refused on its account, and no auth path
-- reads it.
--
-- Not a CHECK ... NOT VALID constraint: NOT VALID still validates every later
-- UPDATE, so an account with a blank name could no longer change its password,
-- be banned, or have its tokens revoked - a data-quality problem would make the
-- account impossible to manage.
--
-- A GENERATED column cannot drift from the data, flips back to false by itself
-- once the fields are complete, and PostgreSQL refuses direct writes.
--
-- qq_number is included like every other PUT /user/profile field (name, phone,
-- qq, major). The import left it blank everywhere because the previous database
-- had no such field, so a first login prompts to collect it once.
--
-- college is excluded: '其他' is a legitimate value and the row does not reveal
-- whether the import defaulted to it, so the affected user has no honest way to
-- clear the prompt. Harmless anyway - those rows already have a blank phone and
-- major.

-- Blankness uses Go's whitespace set, because btrim strips ASCII spaces only
-- and would call an NBSP-only name complete while PUT /user/profile rejects it.
-- Zero-width codepoints are not whitespace to either side and are left to
-- validate.HasControlCharacter. Keep in lockstep with validate.IsBlank -
-- TestProfileCompletenessMatchesSQL feeds both implementations the same inputs.
--
-- IMMUTABLE is required because a generated column may only call immutable
-- functions. The body has no semicolon for the migration runner.
CREATE FUNCTION sl_profile_is_blank(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS
$$ SELECT btrim(value, E' \t\n\r\v\f\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000') = '' $$;

COMMENT ON FUNCTION sl_profile_is_blank(text) IS
    'Whitespace-only test matching Go strings.TrimSpace. Keep in lockstep with internal/validate.IsBlank.';

-- Case-insensitive comparison because the import produced both 'B24040525' and
-- 'b24040525' for the same student_id. STORED evaluates once per write and is
-- computed for every existing row by this ALTER, so no backfill is needed.
ALTER TABLE "user"
    ADD COLUMN profile_needs_completion boolean
    GENERATED ALWAYS AS (
        sl_profile_is_blank(name)
        OR sl_profile_is_blank(phone_number)
        OR sl_profile_is_blank(qq_number)
        OR sl_profile_is_blank(major)
        OR lower(btrim(name)) = lower(btrim(student_id))
    ) STORED;

COMMENT ON COLUMN "user".profile_needs_completion IS
    'TRUE while a required field is blank or name duplicates student_id. Display hint for the completion page, never an authorization input.';

-- Partial so the index only holds flagged accounts. The healthy majority never
-- enters it, keeping the count/list cheap as the table grows.
CREATE INDEX idx_user_profile_needs_completion
    ON "user"(id) WHERE profile_needs_completion;
