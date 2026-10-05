-- Two supporting indexes for user-table queries that had no index shape to
-- hit, both found by the same performance review pass.
--
-- 1. Normalized student IDs. The occupancy guards compare lower(btrim(student_id))
--    so a case-variant spelling of an existing ID cannot slip past them (the
--    legacy import produced exactly that shape), but no index carried the
--    expression: V001's unique constraint is over the raw, case-sensitive value,
--    and V011's partial unique index lives on alumni_requests only. Every
--    ExistsByStudentID / FindLoginEmailByStudentID / recovery-target lookup was
--    a sequential scan, and the recovery approval runs one inside the ticket row
--    lock, where the scan time extends the lock window.
--    Deliberately NOT unique: making it unique would enforce the normalized
--    constraint on rows that already violate it, aborting the migration. The
--    occupancy guards keep enforcing uniqueness in Go plus this index only
--    accelerates the lookups.
--
-- 2. Active administrators. ensureAnotherAdminRemains counts active admins on
--    every admin write (single and batch), and role/state carry no index, so
--    that COUNT was a sequential scan of the largest table - amplified up to
--    500x by the batch update endpoint, all serialized behind the admin
--    advisory lock. The partial index matches the guard's predicate exactly,
--    turning the count into an index-only scan whose size tracks the number of
--    active admins.
--
-- NOTE: no semicolons inside comments - the migration runner splits on them.
CREATE INDEX idx_user_student_id_normalized
    ON "user" (lower(btrim(student_id)));

CREATE INDEX idx_user_active_admins
    ON "user" (id)
    WHERE role = 'admin' AND state <> 'is_deleted';
