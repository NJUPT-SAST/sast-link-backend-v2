-- Extend the profile-completion flag to the product's name rule.
--
-- V015 aligned the flag with the write-path shapes (blank / over-long /
-- control-character), but the product refuses one more shape that lives in the
-- frontend: a name outside the Han + interpunct character set (frontend
-- realNameSchema, lib/validations/name.ts). The backend write paths accepted
-- such a name, so a legacy row holding "AAA" or "John" was called complete by
-- the flag, was never routed to the completion page, and locked every profile
-- edit — the edit form submits the whole profile, and its Han-only validation
-- refused the request for any change at all.
--
-- V016 flags such names (Go side: validate.IsInvalidName, ported to the same
-- block list here) and every write path now refuses them, so the flag reports
-- exactly the shapes an edit would reject: blank / over-long /
-- control-character / out-of-set name for the four banner fields, plus the
-- name = student_id placeholder.
--
-- PostgreSQL has no \p{Script=Han}, so the block list is spelled out literally.
-- The ranges take the superscript strategy: they cover every Han block through
-- Unicode 16 (including Extension I), so a character newer than a browser's
-- Unicode tables may pass here while the frontend still refuses it — a prompt
-- the user can clear. The dangerous drift is the opposite: a Han character the
-- frontend accepts but this list misses would leave a prompt the user cannot
-- clear. Keep the list in lockstep with internal/validate/name.go —
-- TestNameRuleMatchesSQL feeds both halves the same inputs.

CREATE FUNCTION sl_name_invalid(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS
$$ SELECT btrim(value) !~ '^[\x3400-\x4DBF\x4E00-\x9FFF\xF900-\xFAFF\x20000-\x2A6DF\x2A700-\x2B73F\x2B740-\x2B81F\x2B820-\x2CEAF\x2CEB0-\x2EBEF\x2EBF0-\x2EE5F\x2F800-\x2FA1F\x30000-\x3134F\x31350-\x323AF\x00B7\x2027\x0387\x30FB\xFF65]+$' $$;

COMMENT ON FUNCTION sl_name_invalid(text) IS
    'True when the trimmed value holds any character outside the Han + interpunct set (frontend realNameSchema). Keep in lockstep with internal/validate/name.go.';

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
        OR sl_name_invalid(btrim(name))
        OR lower(btrim(name)) = lower(btrim(student_id))
    ) STORED;

COMMENT ON COLUMN "user".profile_needs_completion IS
    'TRUE while a required field is blank, over-long or holds a C0/C1 control character, name holds a character outside the Han + interpunct set, or name duplicates student_id. Display hint for the completion page, never an authorization input.';

CREATE INDEX idx_user_profile_needs_completion
    ON "user"(id) WHERE profile_needs_completion;