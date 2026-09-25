-- Personal badge: one opt-in row per user backing the public /badge/:key.svg
-- embed. Numbered 019 because 017 and 018 are taken by migrations landing
-- through sibling reviews (name-initials search, refresh revoked_reason);
-- golang-migrate does not require consecutive versions. The key is a 256-bit
-- random base64url capability-URL segment stored verbatim: the data it
-- unlocks is exactly the profile the user chose to share publicly, so
-- database exposure grants no privilege beyond links the user is already
-- handing out, while the random key keeps the sequential-id enumeration
-- problem (why /card/:id was removed) out of the public surface.
--
-- The row survives disable: disabled_at marks the sharing state, and toggling
-- never rotates the key — a saved embed URL recovers the moment the owner
-- switches back on, and while off it renders the neutral "closed" card. The
-- key is minted exactly once, on the first enable.
CREATE TABLE badge (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    badge_key   TEXT NOT NULL,
    enabled_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at TIMESTAMPTZ,
    CONSTRAINT uq_badge_user_id UNIQUE (user_id),
    CONSTRAINT uq_badge_badge_key UNIQUE (badge_key)
);
