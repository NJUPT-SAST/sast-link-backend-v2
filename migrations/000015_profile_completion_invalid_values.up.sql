-- Extend the profile-completion flag to the shapes an edit would refuse.
--
-- V010 flagged only two shapes of debris: blank banner fields and a name
-- duplicated from the student ID. But the write path (PUT /user/profile) also
-- rejects two more shapes — an over-long value and one holding a C0/C1 control
-- character. A legacy row whose name is "张三\x01" therefore looked complete to
-- the flag while every edit was refused: the frontend never prompted to fix the
-- name, and once the user filled the genuinely blank fields the flag flipped to
-- false, leaving the unusable value behind permanently and unguided.
--
-- The generated column now reports a field as incomplete exactly when the write
-- path would refuse it. Zero-width codepoints are deliberately NOT flagged:
-- they are not control characters and the write path accepts them.
--
-- Over-length is physically impossible today (V001's varchar(255/20/20/50)
-- refuses to store it), but the column is rebuilt to the full write-path rule
-- so a future widening of the columns cannot silently strand old rows between
-- "accepted by the width check" and "ignored by the flag". The widths here are
-- V001's, mirrored in internal/validate/limits.go — keep them in lockstep.
--
-- The column is recreated so the expression can be replaced (DROP + ADD
-- recomputes every existing row, so no backfill is needed). The partial index
-- rides on the column and is dropped with it, hence the recreate. The helper
-- function is a lockstep partner of validate.HasControlCharacter, like
-- sl_profile_is_blank is of validate.IsBlank.

CREATE FUNCTION sl_has_control_character(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS
$$ SELECT value ~ '[\x01-\x1F\x7F\x80-\x9F]' $$;

COMMENT ON FUNCTION sl_has_control_character(text) IS
    'C0/C1 control-character test matching Go validate.HasControlCharacter (NUL excluded: PostgreSQL cannot store it). Keep in lockstep with internal/validate/email.go.';

ALTER TABLE "user"
    DROP COLUMN profile_needs_completion;

ALTER TABLE "user"
    ADD COLUMN profile_needs_completion boolean
    GENERATED ALWAYS AS (
        sl_profile_is_blank(name)
        OR sl_profile_is_blank(phone_number)
        OR sl_profile_is_blank(qq_number)
        OR sl_profile_is_blank(major)
        OR length(btrim(name)) > 255
        OR length(btrim(phone_number)) > 20
        OR length(btrim(qq_number)) > 20
        OR length(btrim(major)) > 50
        OR sl_has_control_character(btrim(name))
        OR sl_has_control_character(btrim(phone_number))
        OR sl_has_control_character(btrim(qq_number))
        OR sl_has_control_character(btrim(major))
        OR lower(btrim(name)) = lower(btrim(student_id))
    ) STORED;

COMMENT ON COLUMN "user".profile_needs_completion IS
    'TRUE while a required field is blank, over-long, holds a C0/C1 control character, or name duplicates student_id. Display hint for the completion page, never an authorization input.';

CREATE INDEX idx_user_profile_needs_completion
    ON "user"(id) WHERE profile_needs_completion;