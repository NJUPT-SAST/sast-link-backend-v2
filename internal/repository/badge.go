package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// ErrBadgeAlreadyEnabled reports that the user already holds a badge row. The
// unique constraint uq_badge_user_id is the enforcement; this sentinel
// classifies the violation so the service can answer with the badge-specific
// business code.
var ErrBadgeAlreadyEnabled = errors.New("repository: badge already enabled")

// BadgeRepository reads and writes the opt-in badge rows backing the public
// /badge/:key.svg embed.
type BadgeRepository struct {
	database *gorm.DB
}

// NewBadge returns a BadgeRepository bound to database.
func NewBadge(database *gorm.DB) *BadgeRepository {
	return &BadgeRepository{database: database}
}

// Create inserts one badge row. ErrBadgeAlreadyEnabled when the user already
// holds one; any other failure is wrapped for the caller's 500 path.
func (r *BadgeRepository) Create(ctx context.Context, badge *model.Badge) error {
	err := r.database.WithContext(ctx).Create(badge).Error
	if err == nil {
		return nil
	}
	if DuplicateConstraint(err) == "uq_badge_user_id" {
		return ErrBadgeAlreadyEnabled
	}
	return fmt.Errorf("create badge: %w", err)
}

// FindByUserID returns the caller's badge row. ErrNotFound when none exists,
// ErrInvalidArgument on a non-positive id.
func (r *BadgeRepository) FindByUserID(ctx context.Context, userID int64) (*model.Badge, error) {
	if userID <= 0 {
		return nil, ErrInvalidArgument
	}
	var badge model.Badge
	err := r.database.WithContext(ctx).
		Where("user_id = ?", userID).
		Take(&badge).Error
	if err == nil {
		return &badge, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find badge by user id: %w", err)
}

// ReEnable clears the sharing pause on an existing row, keeping its key —
// toggling never rotates the key, so a saved embed URL recovers as-is. It
// reports whether a paused row was actually resumed (false = already enabled
// or no row). enabled_at moves to now: it names the current sharing period.
func (r *BadgeRepository) ReEnable(ctx context.Context, userID int64, now time.Time) (bool, error) {
	if userID <= 0 {
		return false, ErrInvalidArgument
	}
	result := r.database.WithContext(ctx).
		Model(&model.Badge{}).
		Where("user_id = ? AND disabled_at IS NOT NULL", userID).
		Updates(map[string]any{"disabled_at": nil, "enabled_at": now})
	if result.Error != nil {
		return false, fmt.Errorf("re-enable badge: %w", result.Error)
	}
	return result.RowsAffected > 0, nil
}

// Disable pauses sharing on the caller's row, keeping the key. It reports
// whether an enabled row was actually paused (false = already paused or no
// row — disable is idempotent).
func (r *BadgeRepository) Disable(ctx context.Context, userID int64, now time.Time) (bool, error) {
	if userID <= 0 {
		return false, ErrInvalidArgument
	}
	result := r.database.WithContext(ctx).
		Model(&model.Badge{}).
		Where("user_id = ? AND disabled_at IS NULL", userID).
		Update("disabled_at", now)
	if result.Error != nil {
		return false, fmt.Errorf("disable badge: %w", result.Error)
	}
	return result.RowsAffected > 0, nil
}

// FindBadgeTarget resolves a public badge key to its owner's row, refusing
// soft-deleted accounts and paused badges the way FindPublicCardByUserID
// hides deleted users: a closed badge must render the neutral card, and a
// user the owner asked to have removed must not keep a live public badge.
// ErrNotFound when the key is unknown, paused, the owner is deleted, or the
// id is non-positive.
func (r *BadgeRepository) FindBadgeTarget(ctx context.Context, badgeKey string) (*model.Badge, error) {
	if badgeKey == "" {
		return nil, ErrInvalidArgument
	}
	var badge model.Badge
	err := r.database.WithContext(ctx).
		Joins(`JOIN "user" ON "user".id = badge.user_id`).
		Where("badge.badge_key = ? AND badge.disabled_at IS NULL AND \"user\".state <> ?", badgeKey, model.UserStateDeleted).
		Take(&badge).Error
	if err == nil {
		return &badge, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find badge target: %w", err)
}

// DeleteByUserID removes the caller's badge row entirely. Retained for tests
// and administration; the sharing toggle uses Disable/ReEnable.
func (r *BadgeRepository) DeleteByUserID(ctx context.Context, userID int64) (bool, error) {
	if userID <= 0 {
		return false, ErrInvalidArgument
	}
	result := r.database.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&model.Badge{})
	if result.Error != nil {
		return false, fmt.Errorf("delete badge: %w", result.Error)
	}
	return result.RowsAffected > 0, nil
}
