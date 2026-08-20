-- Order matters: the generated column depends on sl_profile_is_blank, so the
-- function cannot be dropped while the column still references it. Dropping the
-- column removes its index with it.
ALTER TABLE "user" DROP COLUMN profile_needs_completion;

DROP FUNCTION sl_profile_is_blank(text);
