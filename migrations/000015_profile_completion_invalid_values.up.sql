-- Extend the profile-completion flag to the shapes the profile write path rejects.
-- This remains a soft signal: it never blocks authentication, authorization, or
-- management updates to an otherwise dirty user row.
--
-- The helper mirrors validate.HasControlCharacter. PostgreSQL cannot store NUL,
-- so the SQL expression covers C0/C1 values that can exist in text columns.
-- Keep migration comments free of semicolons: the project runner splits SQL on
-- semicolons without parsing comments.
CREATE FUNCTION sl_has_control_character(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS
$$ SELECT value ~ '[\x01-\x1F\x7F\x80-\x9F]' $$;

COMMENT ON FUNCTION sl_has_control_character(text) IS
    'C0/C1 control-character test matching Go validate.HasControlCharacter. PostgreSQL NUL is not storable.';

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
    'TRUE while a required field is blank, over-long, holds a C0/C1 control character, or name duplicates student_id. Display hint only.';

CREATE INDEX idx_user_profile_needs_completion
    ON "user"(id) WHERE profile_needs_completion;
