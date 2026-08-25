package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

const maxOutboxDeliveryErrorLength = 1024

// TokenBlacklistOutboxRepository coordinates durable revocation deliveries: the
// rows ride the revoking transaction and the worker invalidates auth-state cache
// entries. The "blacklist" in the name is a legacy naming artifact: the delivery
// target is the auth-state cache, not a blacklist.
type TokenBlacklistOutboxRepository struct {
	database *gorm.DB
}

// NewTokenBlacklistOutbox constructs a durable token-blacklist outbox repository.
func NewTokenBlacklistOutbox(database *gorm.DB) *TokenBlacklistOutboxRepository {
	return &TokenBlacklistOutboxRepository{database: database}
}

// ClaimDue atomically leases up to limit due, unexpired deliveries.
// Claim leases make concurrent workers safe: each row is returned to one worker
// until its lease expires, after which it can be retried by another worker.
//
// The query's two claim states are served by two partial indexes from V004:
// idx_token_blacklist_outbox_due (next_delivery_at, expires_at, id) WHERE
// claim_token IS NULL covers the never-claimed rows, and
// idx_token_blacklist_outbox_claimed_until (claimed_until) WHERE claim_token
// IS NOT NULL covers lease-expired retries. The OR joins the two scans, so the
// ORDER BY cannot ride either index — the due set is bounded by the delivery
// backlog and the sort is in memory. idx_token_blacklist_outbox_expiry
// (expires_at, all rows) serves CleanupExpired's delete scan instead.
func (r *TokenBlacklistOutboxRepository) ClaimDue(
	ctx context.Context,
	now time.Time,
	lease time.Duration,
	limit int,
) ([]model.TokenBlacklistOutbox, error) {
	if lease <= 0 || limit <= 0 || now.IsZero() {
		return nil, fmt.Errorf("claim token blacklist outbox: %w", ErrInvalidArgument)
	}
	claimToken, err := newOutboxClaimToken()
	if err != nil {
		return nil, fmt.Errorf("generate token blacklist outbox claim: %w", err)
	}
	claimedUntil := now.Add(lease)
	var entries []model.TokenBlacklistOutbox
	queryErr := r.database.WithContext(ctx).Raw(`
WITH due AS (
    SELECT id
    FROM token_blacklist_outbox
    WHERE expires_at > ?
      AND next_delivery_at <= ?
      AND (claim_token IS NULL OR claimed_until <= ?)
    ORDER BY next_delivery_at ASC, expires_at ASC, id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT ?
)
UPDATE token_blacklist_outbox AS outbox
SET claim_token = ?,
    claimed_until = ?
FROM due
WHERE outbox.id = due.id
RETURNING outbox.*
`, now, now, now, limit, claimToken, claimedUntil).Scan(&entries).Error
	if queryErr != nil {
		return nil, fmt.Errorf("claim token blacklist outbox: %w", queryErr)
	}
	return entries, nil
}

// Ack permanently removes a delivery owned by claimToken.
// It returns false when a lease expired or the delivery belongs to another worker.
func (r *TokenBlacklistOutboxRepository) Ack(ctx context.Context, id int64, claimToken string) (bool, error) {
	if id <= 0 || claimToken == "" {
		return false, fmt.Errorf("ack token blacklist outbox: %w", ErrInvalidArgument)
	}
	result := r.database.WithContext(ctx).
		Where("id = ? AND claim_token = ?", id, claimToken).
		Delete(&model.TokenBlacklistOutbox{})
	if result.Error != nil {
		return false, fmt.Errorf("ack token blacklist outbox: %w", result.Error)
	}
	return result.RowsAffected == 1, nil
}

// AckMany removes a whole claimed batch in one statement. All rows in a ClaimDue
// batch share one claim token, so a single DELETE IN covers the ack; this is the
// worker's steady-state path (a password change can cut hundreds of sessions at
// once), where per-row DELETEs would serialize dozens of round trips on one core.
func (r *TokenBlacklistOutboxRepository) AckMany(ctx context.Context, ids []int64, claimToken string) (int64, error) {
	if len(ids) == 0 || claimToken == "" {
		return 0, nil
	}
	result := r.database.WithContext(ctx).
		Where("id IN ? AND claim_token = ?", ids, claimToken).
		Delete(&model.TokenBlacklistOutbox{})
	if result.Error != nil {
		return 0, fmt.Errorf("ack token blacklist outbox batch: %w", result.Error)
	}
	return result.RowsAffected, nil
}

// Fail records a failed delivery, clears its lease, and schedules its retry.
// It returns false when a lease expired or the delivery belongs to another worker.
func (r *TokenBlacklistOutboxRepository) Fail(
	ctx context.Context,
	id int64,
	claimToken string,
	attemptedAt time.Time,
	nextDeliveryAt time.Time,
	deliveryError string,
) (bool, error) {
	if id <= 0 || claimToken == "" || attemptedAt.IsZero() || !nextDeliveryAt.After(attemptedAt) {
		return false, fmt.Errorf("fail token blacklist outbox: %w", ErrInvalidArgument)
	}
	result := r.database.WithContext(ctx).
		Model(&model.TokenBlacklistOutbox{}).
		Where("id = ? AND claim_token = ?", id, claimToken).
		Updates(map[string]any{
			"attempt_count":    gorm.Expr("attempt_count + 1"),
			"last_attempt_at":  attemptedAt,
			"last_error":       truncateOutboxDeliveryError(deliveryError),
			"next_delivery_at": nextDeliveryAt,
			"claim_token":      nil,
			"claimed_until":    nil,
		})
	if result.Error != nil {
		return false, fmt.Errorf("fail token blacklist outbox: %w", result.Error)
	}
	return result.RowsAffected == 1, nil
}

// CleanupExpired deletes deliveries whose JWTs can no longer be blacklisted.
func (r *TokenBlacklistOutboxRepository) CleanupExpired(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		return 0, fmt.Errorf("cleanup token blacklist outbox: %w", ErrInvalidArgument)
	}
	result := r.database.WithContext(ctx).
		Where("expires_at <= ?", now).
		Delete(&model.TokenBlacklistOutbox{})
	if result.Error != nil {
		return 0, fmt.Errorf("cleanup token blacklist outbox: %w", result.Error)
	}
	return result.RowsAffected, nil
}

func newOutboxClaimToken() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func truncateOutboxDeliveryError(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= maxOutboxDeliveryErrorLength {
		return value
	}
	return value[:maxOutboxDeliveryErrorLength]
}
