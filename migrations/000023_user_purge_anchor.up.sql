-- Physical purge anchor for closed accounts. DELETE /admin/users/:id stays a
-- soft close so restore keeps its window, but the close transaction now stamps
-- deleted_at and the retention worker hard-deletes rows whose stamp is older
-- than RETENTION_DELETED_USER_AGE (default 30 days, 0 disables). Legacy
-- is_deleted rows are backfilled with the migration moment: every existing
-- closed account gets one full grace window instead of being judged against an
-- age nobody recorded.
ALTER TABLE "user"
    ADD COLUMN deleted_at TIMESTAMPTZ;

UPDATE "user" SET deleted_at = now() WHERE state = 'is_deleted' AND deleted_at IS NULL;

COMMENT ON COLUMN "user".deleted_at IS
    'Written by the account-close transaction, cleared by restore. The retention worker physically deletes the row (cascading profile, identities and token metadata, nulling audit and ticket references) once deleted_at is older than the configured grace window. NULL on every live account.';
