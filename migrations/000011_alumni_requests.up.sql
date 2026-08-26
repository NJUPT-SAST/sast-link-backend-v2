-- Alumni account-request tickets. Graduated members cannot register (the
-- register flow emails a dead school mailbox) and had no way to ask, so this
-- table is the intake. A structured ticket rather than inbound email, because
-- an SMTP sender is forgeable: identity verification stays human, and the table
-- only automates the transcription.
CREATE TYPE alumni_request_status_enum AS ENUM ('pending', 'approved', 'rejected');

-- TEXT rather than VARCHAR(n): the length rules live in internal/validate and
-- the service layer still enforces them on every field copied into "user" on
-- approval, so a schema copy would only be one more thing an ALTER has to find.
CREATE TABLE alumni_requests (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    student_id      TEXT NOT NULL,
    login_email     TEXT NOT NULL,
    personal_email  TEXT NOT NULL,
    phone_number    TEXT NOT NULL,
    qq_number       TEXT NOT NULL,
    college         college_enum NOT NULL DEFAULT '其他',
    major           TEXT NOT NULL,
    join_year       TEXT NOT NULL,
    department_note TEXT NOT NULL DEFAULT '',
    note            TEXT NOT NULL DEFAULT '',
    status          alumni_request_status_enum NOT NULL DEFAULT 'pending',
    reject_reason   TEXT NOT NULL DEFAULT '',
    created_user_id BIGINT REFERENCES "user"(id) ON DELETE SET NULL,
    reviewed_by     BIGINT REFERENCES "user"(id) ON DELETE SET NULL,
    reviewed_at     TIMESTAMPTZ,
    notified_at     TIMESTAMPTZ,
    notify_attempts INT NOT NULL DEFAULT 0,
    client_ip       TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE alumni_requests IS
    'Alumni account-request tickets. Identity verification is human. Approval provisions an account in one transaction with the status write.';

COMMENT ON COLUMN alumni_requests.major IS
    'Required by the service layer even though the column allows empty, because a blank major is what V010 profile_needs_completion flags.';

COMMENT ON COLUMN alumni_requests.notified_at IS
    'When the result email was confirmed sent. NULL means not yet delivered, which is what the console filters on to find the backlog.';

COMMENT ON COLUMN alumni_requests.notify_attempts IS
    'Incremented before each send attempt, so a process killed mid-send leaves evidence it tried rather than losing the attempt.';

COMMENT ON COLUMN alumni_requests.created_user_id IS
    'The provisioned account. ON DELETE SET NULL keeps the ticket history after the account is closed.';

COMMENT ON COLUMN alumni_requests.client_ip IS
    'Submitter address, kept for abuse tracing and rate-limit forensics. Never returned in a response.';

-- One open ticket per student ID. Partial on status so a rejected applicant may
-- resubmit while a pending ticket blocks duplicates. lower(btrim(...)) folds
-- the case variance the import produced.
CREATE UNIQUE INDEX uq_alumni_requests_pending_student
    ON alumni_requests (lower(btrim(student_id))) WHERE status = 'pending';

-- The reviewer's queue: filter by status, newest first.
CREATE INDEX idx_alumni_requests_status_created
    ON alumni_requests (status, created_at DESC);

-- The notification backlog. Partial so a healthy ticket (notified_at set)
-- never enters it.
CREATE INDEX idx_alumni_requests_pending_notification
    ON alumni_requests (id) WHERE status <> 'pending' AND notified_at IS NULL;

-- Reuses V001's update_updated_at_column, already shared by "user", profile,
-- identities and oauth_clients.
CREATE TRIGGER trg_alumni_requests_updated_at
    BEFORE UPDATE ON alumni_requests FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
