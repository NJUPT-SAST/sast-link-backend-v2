-- V017 down: drop the initials column first, then the function once no
-- column references it anymore. The stored data is fully derived from name,
-- so nothing is lost.

ALTER TABLE "user" DROP COLUMN name_initials;

DROP FUNCTION sl_name_initials(text);
