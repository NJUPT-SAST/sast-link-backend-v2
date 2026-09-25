-- V017 down: drop the initials column first, then the function once no
-- column references it anymore. The stored data is fully derived from name,
-- so nothing is lost.

DROP INDEX idx_user_phone_search;
DROP INDEX idx_profile_search;
DROP INDEX idx_user_search;
-- Keep pg_trgm: it may predate this migration or have other consumers.
ALTER TABLE "user" DROP COLUMN name_initials;

DROP FUNCTION sl_name_initials(text);
