-- Drop order matters: the status column depends on the enum type, and dropping
-- the table removes its indexes and updated_at trigger.
--
-- update_updated_at_column is deliberately NOT dropped: it belongs to V001 and
-- four other tables still use it.
DROP TABLE alumni_requests;

DROP TYPE alumni_request_status_enum;
