-- Restore V010's generated column: blank banner fields or a name duplicated
-- from the student ID. The sl_profile_is_blank function predates V015 and stays
-- (sl_has_control_character is only referenced by the column being recreated, so
-- it drops with it).

ALTER TABLE "user"
    DROP COLUMN profile_needs_completion;

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

CREATE INDEX idx_user_profile_needs_completion
    ON "user"(id) WHERE profile_needs_completion;

DROP FUNCTION sl_has_control_character(text);