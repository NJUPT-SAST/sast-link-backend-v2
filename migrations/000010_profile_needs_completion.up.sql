-- Flag the accounts whose required "user" columns still carry migration debris.
--
-- The V001 columns name/phone_number/major are NOT NULL but have no DEFAULT (or,
-- for major, DEFAULT ''), so NOT NULL never excluded the empty string. Accounts
-- imported from the previous database therefore hold two shapes of unusable
-- value: blank required fields, and a name that was filled in with the student
-- ID. Both are rejected by the current input layer
-- (internal/service/session/profile.go, internal/service/adminuser/validate.go),
-- so this is pure legacy state rather than something still being produced. The
-- flag exists so the frontend can route those users to a completion page.
--
-- This is a soft signal only. No request is refused on account of it, and no
-- authentication or authorization path reads it.
--
-- Deliberately NOT a CHECK ... NOT VALID constraint. NOT VALID only skips the
-- one-time full-table validation. Every later UPDATE still validates the whole
-- row, including updates that touch none of the offending columns. This service
-- writes "user" rows to bump token_version (password change, demotion, account
-- close - the "cut access now" operations) and to rehash a legacy password in
-- place. Under a NOT VALID constraint an account with a blank name could no
-- longer change its password, be banned, or have its tokens revoked: a data
-- quality problem escalated into denial of service.
--
-- A GENERATED column has none of that coupling. It is a pure function of the
-- row's own values, so it cannot drift from the data the way an application-
-- maintained boolean would, it flips back to false by itself as soon as the user
-- completes the fields, and PostgreSQL refuses any attempt to write it directly.
--
-- qq_number is included for the same reason as phone_number: every NOT NULL
-- banner field the user can fill in through PUT /user/profile (name, phone,
-- qq, major) is treated alike. The import left it empty for every row because
-- the previous database had no such field, so a first login will prompt to
-- collect it once, which is the whole point of the guided completion.
--
-- college is deliberately absent. '其他' is a legitimate college_enum
-- member, and nothing in the row distinguishes "the import defaulted to it" from
-- "the user really chose it", so treating it as debris would raise a prompt that
-- the affected user has no honest way to clear. It costs nothing to leave out:
-- every row that holds the default also has a blank phone_number and major, so
-- the flag already covers them.

-- Blankness has to be decided the same way in SQL and in Go, because the Go rule
-- is what accepts or rejects the user's fix. PostgreSQL's one-argument
-- btrim(text) strips ASCII spaces only, while Go's strings.TrimSpace strips the
-- whole Unicode whitespace set, so `btrim(name) = ''` would call a name holding
-- a single NBSP complete while PUT /user/profile refuses to accept any edit to
-- it - the user is told nothing is wrong and still cannot submit. The character
-- set below is Go's: unicode.IsSpace plus U+0085 and U+00A0. Zero-width
-- codepoints (U+200B..U+200D, U+FEFF) are not whitespace to either side and are
-- handled by validate.HasControlCharacter instead, so they are not listed here.
--
-- Keep in lockstep with validate.IsBlank. TestProfileCompletenessMatchesSQL
-- feeds both implementations the same inputs and fails when they disagree.
--
-- IMMUTABLE is required: a generated column may only call immutable functions.
-- The body contains no semicolon, which the migration runner would treat as a
-- statement separator.
CREATE FUNCTION sl_profile_is_blank(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS
$$ SELECT btrim(value, E' \t\n\r\v\f\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000') = '' $$;

COMMENT ON FUNCTION sl_profile_is_blank(text) IS
    'Whitespace-only test matching Go strings.TrimSpace. Keep in lockstep with internal/validate.IsBlank.';

-- The name/student_id comparison is case-insensitive on purpose: the imported
-- rows hold both 'B24040525' and 'b24040525' against the same student_id, and a
-- case-sensitive test would silently pass the lowercase half.
--
-- STORED evaluates once per write and is computed for every existing row by this
-- ALTER, so no backfill statement is needed.
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

-- Partial index so counting or listing the affected accounts stays cheap as the
-- table grows. The flag is false for a healthy account, so the index only ever
-- holds the backlog.
CREATE INDEX idx_user_profile_needs_completion
    ON "user"(id) WHERE profile_needs_completion;
