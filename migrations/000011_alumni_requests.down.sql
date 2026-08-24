-- Order matters: the table's status column depends on the enum type, so the type
-- cannot be dropped while the table still uses it. Dropping the table removes
-- its indexes and its updated_at trigger with it.
--
-- update_updated_at_column is deliberately NOT dropped. It belongs to V001 and
-- four other tables still use it.
DROP TABLE alumni_requests;

DROP TYPE alumni_request_status_enum;
