-- V014: user.state manual-pin flag for the derived state machine.
--
-- user.state (njupter / on_sast / retired_sast) becomes derived from
-- role + student_id enrollment year + the current academic year, computed in Go
-- (internal/validate.DeriveState, single source of truth — never copied into
-- SQL). state_manual = TRUE means an administrator pinned the value by hand and
-- every derivation path (write-side derivation and the retention-batch recompute)
-- must skip the row. is_deleted stays on the manual DELETE channel regardless.
--
-- Existing rows all get FALSE: the migration does not rewrite any state value.
-- The first retention-batch pass calibrates live rows to the derived values.
ALTER TABLE "user"
    ADD COLUMN state_manual BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN "user".state_manual IS
    'TRUE when an administrator pinned state by hand (PUT /admin/users/:id with state). Derived-state paths (write-side derivation, retention batch) skip the row while pinned — state_auto=true on PUT re-enables derivation. is_deleted is the manual DELETE channel and shadows this flag.';