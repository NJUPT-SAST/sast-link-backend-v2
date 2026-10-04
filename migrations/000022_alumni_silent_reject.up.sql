-- Silent rejection for alumni account-request tickets. A mistaken submission
-- (typically a freshman who registered on their own after filing) carries no
-- result the applicant needs to hear about, so the reviewer may reject it
-- without emailing anyone. The flag persists the delivery choice rather than
-- encoding it implicitly (notified_at set with notify_attempts = 0): the
-- resend endpoint refuses silent tickets and the console renders them as
-- never-notified, both of which need to read the choice back.
ALTER TABLE alumni_requests
    ADD COLUMN silently_rejected BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN alumni_requests.silently_rejected IS
    'TRUE when the rejection chose not to email the applicant (e.g. they had already self-registered). The rejecting transaction also sets notified_at so the restart requeue sweep (notified_at IS NULL AND notify_attempts = 0) never picks the ticket up, and resend is refused.';
