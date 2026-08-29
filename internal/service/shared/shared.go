// Package shared holds the small, stateless helpers that more than one service
// package was copying. They live here so a single definition cannot drift into
// per-package variants (audit findings #2, #24).
package shared

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// DurationOrDefault returns value when positive, else fallback.
func DurationOrDefault(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

// NullableString returns a pointer to s, or nil for an empty value. The pointer
// is what model columns expect: NULL on the wire instead of an empty string.
func NullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ActorClientID resolves what to record as the acting client on audit rows: the
// actor's client id when present, otherwise the built-in console client. Both
// sides are trimmed — a legacy azp carrying surrounding whitespace would
// otherwise be recorded verbatim — and an empty result means the caller stores
// NULL.
func ActorClientID(actor, internalClientID string) string {
	if actor = strings.TrimSpace(actor); actor != "" {
		return actor
	}
	return strings.TrimSpace(internalClientID)
}

// TokenBlacklist invalidates the auth-state cache entries for revoked access
// tokens. Revocation is authoritative in PostgreSQL; this clears the short-TTL
// cache so the middleware's next request re-checks the database immediately.
type TokenBlacklist interface {
	DeleteAuthStates(ctx context.Context, jtis []string) error
}

// DeliverBlacklist clears the auth-state cache for revoked access tokens. The
// durable delivery is the outbox row written in the revoking transaction; this
// synchronous call closes the stale window so a just-revoked token is rejected
// on the next request rather than riding out the cache TTL. Entries whose
// access token has already expired need no cache entry, and an empty TokenID
// cannot be a real cache key, so both are filtered out before delivery.
func DeliverBlacklist(ctx context.Context, blacklist TokenBlacklist, entries []model.BlacklistEntry, now time.Time) {
	if blacklist == nil || len(entries) == 0 {
		return
	}
	jtis := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.ExpiresAt.Sub(now) <= 0 || strings.TrimSpace(entry.TokenID) == "" {
			continue
		}
		jtis = append(jtis, entry.TokenID)
	}
	if len(jtis) == 0 {
		return
	}
	if err := blacklist.DeleteAuthStates(ctx, jtis); err != nil {
		// The same-transaction outbox row guarantees a worker retry, so a failed
		// synchronous delivery is expected degradation, not an error.
		slog.WarnContext(ctx, "deliver auth-state invalidation, outbox worker will retry", "count", len(jtis), "error", err)
	}
}
