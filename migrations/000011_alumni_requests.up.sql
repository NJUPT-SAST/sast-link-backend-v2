-- Alumni account-request tickets.
--
-- Graduated members cannot register: the first step of /auth/register sends a
-- code to an @njupt.edu.cn or @sast.fun address, and a deactivated school
-- mailbox makes that a dead end. The console can already provision an account,
-- but there was no way for the alumnus to ask.
--
-- A structured ticket rather than an inbound-email parser. The mailer is
-- outbound-only, and more importantly an SMTP sender is forgeable while a
-- student ID plus a name is not a secret among graduates - automatic approval on
-- a received email would hand anyone the ability to open an account. Identity
-- verification stays human. What this table automates is the transcription
-- labour, not the judgement.
CREATE TYPE alumni_request_status_enum AS ENUM ('pending', 'approved', 'rejected');

-- Column widths are TEXT rather than VARCHAR(n) because the length rules live in
-- internal/validate, where both this flow and the console read them from the same
-- constants. A second copy in the schema is one more thing an ALTER TABLE has to
-- find. The service layer still enforces the V001 widths on every field that
-- gets copied into "user" on approval - a ticket holding a 300-character name
-- would otherwise be accepted here and fail at approval time, which is the worst
-- place to discover it.
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

-- One open ticket per student ID. Partial on status so a rejected applicant can
-- correct their details and resubmit, while a pending one cannot flood the queue.
-- lower(btrim(...)) matches how the import produced both 'B24040525' and
-- 'b24040525' for the same person.
CREATE UNIQUE INDEX uq_alumni_requests_pending_student
    ON alumni_requests (lower(btrim(student_id))) WHERE status = 'pending';

-- The reviewer's queue: filter by status, newest first.
CREATE INDEX idx_alumni_requests_status_created
    ON alumni_requests (status, created_at DESC);

-- The notification backlog. Partial, so it holds only the rows that need
-- attention: a healthy ticket has a non-NULL notified_at and never enters it.
CREATE INDEX idx_alumni_requests_pending_notification
    ON alumni_requests (id) WHERE status <> 'pending' AND notified_at IS NULL;

-- Reuse V001's trigger function rather than defining another one. It is already
-- shared by "user", profile, identities and oauth_clients.
CREATE TRIGGER trg_alumni_requests_updated_at
    BEFORE UPDATE ON alumni_requests FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
