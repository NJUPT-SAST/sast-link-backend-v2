-- The student-ID occupancy guards compare lower(btrim(student_id)) so a
-- case-variant spelling of an existing ID cannot slip past them (the legacy
-- import produced exactly that shape), but the user table carries no index for
-- the expression: V001's unique constraint is over the raw, case-sensitive
-- value, and V011's partial unique index lives on alumni_requests only. Every
-- ExistsByStudentID / FindLoginEmailByStudentID / recovery-target lookup was a
-- sequential scan, and the recovery approval runs one inside the ticket row
-- lock, where the scan time extends the lock window.
-- Deliberately NOT unique: making it unique would enforce the normalized
-- constraint on rows that already violate it, aborting the migration. The
-- occupancy guards keep enforcing uniqueness in Go plus this index only
-- accelerates the lookups.
-- NOTE: no semicolons inside comments - the migration runner splits on them.
CREATE INDEX idx_user_student_id_normalized
    ON "user" (lower(btrim(student_id)));
