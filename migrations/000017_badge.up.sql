-- Personal badge: one opt-in row per user backing the public /badge/:key.svg
-- embed. The key is a 256-bit random base64url capability-URL segment stored
-- verbatim: the data it unlocks is exactly the profile the user chose to share
-- publicly, so database exposure grants no privilege beyond links the user is
-- already handing out, while the random key keeps the sequential-id
-- enumeration problem (why /card/:id was removed) out of the public surface.
-- Row existence is the enable flag: deleting the row disables the badge, and
-- re-enabling mints a fresh key so a retired link never resurrects.
CREATE TABLE badge (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    badge_key  TEXT NOT NULL,
    enabled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_badge_user_id UNIQUE (user_id),
    CONSTRAINT uq_badge_badge_key UNIQUE (badge_key)
);
