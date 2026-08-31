-- Recovery intent for alumni account-request tickets. 'provision' opens a new
-- account (V011's original and only behavior). 'recover' targets the account an
-- existing student ID already holds: approval binds PersonalEmail as that
-- account's other_mail identity instead of provisioning, so a graduate whose
-- school mailbox died before they bound anything can regain access without a
-- second account. Old rows default to provision, which reproduces their
-- original behavior exactly.
ALTER TABLE alumni_requests
    ADD COLUMN intent TEXT NOT NULL DEFAULT 'provision';

COMMENT ON COLUMN alumni_requests.intent IS
    '''provision'' opens a new account on approval. ''recover'' binds personal_email to the account the student_id already names, restoring access instead of duplicating it. The pending-student unique index covers both intents, so one student ID cannot hold an open ticket of each kind.';

-- Intent is intentionally not indexed or enum-typed: it is written once at
-- submission, filtered nowhere at scale, and its rules live in internal/model
-- and the service layer.
