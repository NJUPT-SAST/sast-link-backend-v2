-- Restore V015's generated column: blank / over-long / control-character
-- Keep the SQL body free of semicolons inside comments because the migration
-- runner splits statements without parsing SQL comments.
-- sl_has_control_character predate V016 and stay. The name helper is dropped
-- after the generated column no longer references it.

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

DROP FUNCTION sl_name_invalid(text)