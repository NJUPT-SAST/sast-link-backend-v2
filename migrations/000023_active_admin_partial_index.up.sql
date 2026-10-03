-- ensureAnotherAdminRemains counts active administrators on every admin write
-- (single and batch), and the user table has no index over role or state, so
-- that COUNT was a sequential scan of the largest table - amplified up to 500x
-- by the batch update endpoint, all serialized behind the admin advisory lock.
-- A partial index over exactly the predicate the guard counts turns it into an
-- index-only scan whose size is the (tiny) number of active admins.
-- NOTE: no semicolons inside comments - the migration runner splits on them.
CREATE INDEX idx_user_active_admins
    ON "user" (id)
    WHERE role = 'admin' AND state <> 'is_deleted';
