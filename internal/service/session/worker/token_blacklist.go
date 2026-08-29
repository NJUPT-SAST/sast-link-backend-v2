// Package sessionworker runs background delivery and cleanup tasks for session token revocation.
package sessionworker

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/shared"
)

const (
	defaultTokenBlacklistInterval    = time.Second
	defaultTokenBlacklistLease       = 30 * time.Second
	defaultTokenBlacklistBatchSize   = 100
	defaultTokenBlacklistMaxBackoff  = 30 * time.Second
	defaultTokenBlacklistCleanupRate = time.Hour
)

type TokenBlacklistOutbox interface {
	ClaimDue(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]model.TokenBlacklistOutbox, error)
	AckMany(ctx context.Context, ids []int64, claimToken string) (int64, error)
	Fail(ctx context.Context, id int64, claimToken string, attemptedAt, nextDeliveryAt time.Time, deliveryError string) (bool, error)
	CleanupExpired(ctx context.Context, now time.Time) (int64, error)
}

type AuthStateInvalidator interface {
	// DeleteAuthStates removes the per-token auth-state cache entries for a set
	// of JTIs in one pipeline call.
	DeleteAuthStates(ctx context.Context, jtis []string) error
}

// TokenBlacklist delivers durable JWT revocations from the outbox to the
// auth-state cache: every revoked JTI's cached state is deleted so the
// middleware cannot admit a token whose DB row says revoked. The outbox rows are
// keyed by token ID, and delivery targets the auth-state cache.
type TokenBlacklist struct {
	Outbox          TokenBlacklistOutbox
	AuthState       AuthStateInvalidator
	Interval        time.Duration
	Lease           time.Duration
	BatchSize       int
	MaxBackoff      time.Duration
	CleanupInterval time.Duration
	Clock           auth.Clock
}

// Run processes due deliveries until ctx is canceled.
func (w TokenBlacklist) Run(ctx context.Context) error {
	if err := w.validate(); err != nil {
		return err
	}
	interval := shared.DurationOrDefault(w.Interval, defaultTokenBlacklistInterval)
	cleanupInterval := shared.DurationOrDefault(w.CleanupInterval, defaultTokenBlacklistCleanupRate)
	// A timer lets an empty outbox sleep at maxBackoff.
	dueTimer := time.NewTimer(interval)
	defer dueTimer.Stop()
	cleanupTicker := time.NewTicker(cleanupInterval)
	defer cleanupTicker.Stop()

	w.processDue(ctx)
	w.cleanupExpired(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-dueTimer.C:
			dueTimer.Reset(w.processDue(ctx))
		case <-cleanupTicker.C:
			w.cleanupExpired(ctx)
		}
	}
}

// processDue claims one batch, invalidates the auth-state cache entries in a
// single pipeline call, and acks or fails each entry. It returns the interval
// until the next pass: the base interval after any work, maxBackoff when the
// outbox was empty.
//
// Backing off on an idle queue is safe: cache invalidation only closes the
// residual stale window, while the authoritative DB revoked_at check covers the
// same tokens from the moment the revoking transaction commits.
func (w TokenBlacklist) processDue(ctx context.Context) time.Duration {
	base := shared.DurationOrDefault(w.Interval, defaultTokenBlacklistInterval)
	maxBackoff := shared.DurationOrDefault(w.MaxBackoff, defaultTokenBlacklistMaxBackoff)
	now := w.now()
	entries, err := w.Outbox.ClaimDue(ctx, now, w.lease(), w.batchSize())
	if err != nil {
		if ctx.Err() == nil {
			slog.Error("claim token blacklist outbox", "error", err)
		}
		return maxBackoff
	}
	if len(entries) == 0 {
		return maxBackoff
	}

	var claimToken string
	expiredIDs := make([]int64, 0, len(entries))
	deliverable := make([]string, 0, len(entries))
	deliverableIDs := make([]int64, 0, len(entries))
	for _, entry := range entries {
		if entry.ClaimToken == nil || strings.TrimSpace(*entry.ClaimToken) == "" {
			slog.Error("deliver token blacklist outbox", "id", entry.ID, "error", "missing claim token")
			continue
		}
		claimToken = *entry.ClaimToken
		if entry.ExpiresAt.Sub(now) <= 0 {
			expiredIDs = append(expiredIDs, entry.ID)
			continue
		}
		deliverable = append(deliverable, entry.TokenID)
		deliverableIDs = append(deliverableIDs, entry.ID)
	}
	if len(expiredIDs) > 0 {
		w.ackMany(ctx, expiredIDs, claimToken)
	}
	if len(deliverable) == 0 {
		return base
	}

	// Deleting the auth-state cache entry for each revoked JTI is what makes the
	// revocation effective: the middleware serves state from the cache, and a
	// stale cached state would otherwise admit a token whose DB row says revoked.
	if err := w.AuthState.DeleteAuthStates(ctx, deliverable); err != nil {
		deliverableSet := make(map[string]struct{}, len(deliverable))
		for _, jti := range deliverable {
			deliverableSet[jti] = struct{}{}
		}
		for _, entry := range entries {
			if _, ok := deliverableSet[entry.TokenID]; !ok {
				continue
			}
			// Retry backoff grows with attempt count, so each failed row keeps its
			// own next_delivery_at and the failures stay per-row.
			next := now.Add(w.retryBackoff(entry.AttemptCount))
			updated, failErr := w.Outbox.Fail(ctx, entry.ID, *entry.ClaimToken, now, next, err.Error())
			if failErr != nil {
				slog.Error("fail token blacklist outbox", "id", entry.ID, "error", failErr)
			} else if !updated {
				slog.Warn("token blacklist outbox lease lost after delivery failure", "id", entry.ID)
			}
		}
		return base
	}
	w.ackMany(ctx, deliverableIDs, claimToken)
	return base
}

// ackMany removes a batch of delivered rows in one statement. All rows share the
// batch's claim token, so a single DELETE IN covers them.
func (w TokenBlacklist) ackMany(ctx context.Context, ids []int64, claimToken string) {
	acked, err := w.Outbox.AckMany(ctx, ids, claimToken)
	if err != nil {
		slog.Error("ack token blacklist outbox batch", "error", err)
	} else if acked != int64(len(ids)) {
		slog.Warn("token blacklist outbox lease lost before ack", "acked", acked, "want", len(ids))
	}
}

func (w TokenBlacklist) cleanupExpired(ctx context.Context) {
	if _, err := w.Outbox.CleanupExpired(ctx, w.now()); err != nil && ctx.Err() == nil {
		slog.Error("cleanup token blacklist outbox", "error", err)
	}
}

func (w TokenBlacklist) retryBackoff(attemptCount int) time.Duration {
	if attemptCount < 0 {
		attemptCount = 0
	}
	if attemptCount > 30 {
		attemptCount = 30
	}
	backoff := time.Second * time.Duration(1<<attemptCount)
	maxBackoff := shared.DurationOrDefault(w.MaxBackoff, defaultTokenBlacklistMaxBackoff)
	if backoff > maxBackoff {
		return maxBackoff
	}
	return backoff
}

func (w TokenBlacklist) validate() error {
	if w.Outbox == nil || w.AuthState == nil {
		return fmt.Errorf("token blacklist worker requires outbox and auth-state invalidator")
	}
	if w.Interval < 0 || w.Lease < 0 || w.BatchSize < 0 || w.MaxBackoff < 0 || w.CleanupInterval < 0 {
		return fmt.Errorf("token blacklist worker durations and batch size must not be negative")
	}
	return nil
}

func (w TokenBlacklist) now() time.Time {
	clock := w.Clock
	if clock == nil {
		clock = auth.SystemClock
	}
	return clock.Now().UTC()
}

func (w TokenBlacklist) lease() time.Duration {
	return shared.DurationOrDefault(w.Lease, defaultTokenBlacklistLease)
}

func (w TokenBlacklist) batchSize() int {
	if w.BatchSize > 0 {
		return w.BatchSize
	}
	return defaultTokenBlacklistBatchSize
}
