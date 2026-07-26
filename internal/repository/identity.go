package repository

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// IdentityRepository persists and retrieves third-party login bindings.
type IdentityRepository struct {
	database *gorm.DB
}

// NewIdentity constructs an IdentityRepository backed by database.
func NewIdentity(database *gorm.DB) *IdentityRepository {
	return &IdentityRepository{database: database}
}

// CountByUserAndProvider counts identities of the given provider owned by userID.
func (r *IdentityRepository) CountByUserAndProvider(ctx context.Context, userID int64, provider model.LoginMethod) (int64, error) {
	var count int64
	if err := r.database.WithContext(ctx).Model(&model.Identity{}).
		Where("user_id = ? AND provider = ?", userID, provider).
		Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count identities by user and provider: %w", err)
	}
	return count, nil
}

// FindByProviderID returns the identity bound to the given provider+providerID pair.
func (r *IdentityRepository) FindByProviderID(ctx context.Context, provider model.LoginMethod, providerID string) (*model.Identity, error) {
	var identity model.Identity
	err := r.database.WithContext(ctx).
		Where("provider = ? AND provider_id = ?", provider, providerID).
		First(&identity).Error
	if err == nil {
		return &identity, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find identity by provider and provider_id: %w", err)
}

// CreateWithinLimit inserts a new identity binding only while the owning user
// holds fewer than limit identities of the same provider. The user row is
// locked first so concurrent binds serialize and cannot exceed the cap.
func (r *IdentityRepository) CreateWithinLimit(ctx context.Context, identity *model.Identity, limit int64) error {
	if identity == nil || limit <= 0 {
		return ErrInvalidArgument
	}
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		var lockedUser model.User
		if err := transaction.
			Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id").
			Where("id = ?", identity.UserID).
			First(&lockedUser).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return fmt.Errorf("lock user for identity insert: %w", err)
		}
		var count int64
		if err := transaction.Model(&model.Identity{}).
			Where("user_id = ? AND provider = ?", identity.UserID, identity.Provider).
			Count(&count).Error; err != nil {
			return fmt.Errorf("count identities under lock: %w", err)
		}
		if count >= limit {
			return ErrLimitExceeded
		}
		if err := transaction.Create(identity).Error; err != nil {
			return fmt.Errorf("create identity: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrLimitExceeded) || errors.Is(err, ErrNotFound) {
			return err
		}
		return fmt.Errorf("create identity within limit: %w", err)
	}
	return nil
}
