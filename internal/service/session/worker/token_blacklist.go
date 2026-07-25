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
	Ack(ctx context.Context, id int64, claimToken string) (bool, error)
	Fail(ctx context.Context, id int64, claimToken string, attemptedAt, nextDeliveryAt time.Time, deliveryError string) (bool, error)
	CleanupExpired(ctx context.Context, now time.Time) (int64, error)
}

type JTIBlacklist interface {
	BlacklistJTI(ctx context.Context, jti string, ttl time.Duration) error
}

// TokenBlacklist delivers durable JWT revocations from PostgreSQL to Redis.
type TokenBlacklist struct {
	Outbox          TokenBlacklistOutbox
	Blacklist       JTIBlacklist
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
	interval := durationOrDefault(w.Interval, defaultTokenBlacklistInterval)
	cleanupInterval := durationOrDefault(w.CleanupInterval, defaultTokenBlacklistCleanupRate)
	deliveryTicker := time.NewTicker(interval)
	cleanupTicker := time.NewTicker(cleanupInterval)
	defer deliveryTicker.Stop()
	defer cleanupTicker.Stop()

	w.processDue(ctx)
	w.cleanupExpired(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-deliveryTicker.C:
			w.processDue(ctx)
		case <-cleanupTicker.C:
			w.cleanupExpired(ctx)
		}
	}
}

func (w TokenBlacklist) processDue(ctx context.Context) {
	now := w.now()
	entries, err := w.Outbox.ClaimDue(ctx, now, w.lease(), w.batchSize())
	if err != nil {
		if ctx.Err() == nil {
			slog.Error("claim token blacklist outbox", "error", err)
		}
		return
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		w.deliver(ctx, entry)
	}
}

func (w TokenBlacklist) deliver(ctx context.Context, entry model.TokenBlacklistOutbox) {
	if entry.ClaimToken == nil || strings.TrimSpace(*entry.ClaimToken) == "" {
		slog.Error("deliver token blacklist outbox", "id", entry.ID, "error", "missing claim token")
		return
	}
	now := w.now()
	ttl := entry.ExpiresAt.Sub(now)
	if ttl <= 0 {
		w.ack(ctx, entry)
		return
	}
	if err := w.Blacklist.BlacklistJTI(ctx, entry.TokenID, ttl); err != nil {
		next := now.Add(w.retryBackoff(entry.AttemptCount))
		updated, failErr := w.Outbox.Fail(ctx, entry.ID, *entry.ClaimToken, now, next, err.Error())
		if failErr != nil {
			slog.Error("fail token blacklist outbox", "id", entry.ID, "error", failErr)
		} else if !updated {
			slog.Warn("token blacklist outbox lease lost after delivery failure", "id", entry.ID)
		}
		return
	}
	w.ack(ctx, entry)
}

func (w TokenBlacklist) ack(ctx context.Context, entry model.TokenBlacklistOutbox) {
	acked, err := w.Outbox.Ack(ctx, entry.ID, *entry.ClaimToken)
	if err != nil {
		slog.Error("ack token blacklist outbox", "id", entry.ID, "error", err)
	} else if !acked {
		slog.Warn("token blacklist outbox lease lost before ack", "id", entry.ID)
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
	maxBackoff := durationOrDefault(w.MaxBackoff, defaultTokenBlacklistMaxBackoff)
	if backoff > maxBackoff {
		return maxBackoff
	}
	return backoff
}

func (w TokenBlacklist) validate() error {
	if w.Outbox == nil || w.Blacklist == nil {
		return fmt.Errorf("token blacklist worker requires outbox and blacklist")
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
	return durationOrDefault(w.Lease, defaultTokenBlacklistLease)
}

func (w TokenBlacklist) batchSize() int {
	if w.BatchSize > 0 {
		return w.BatchSize
	}
	return defaultTokenBlacklistBatchSize
}

func durationOrDefault(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}
