package repository

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
)

type profileRepo struct {
	db *gorm.DB
}

// NewProfileRepo creates a new ProfileRepository.
func NewProfileRepo(db *gorm.DB) ProfileRepository {
	return &profileRepo{db: db}
}

func (r *profileRepo) FindByUserID(ctx context.Context, userID int64) (*domain.Profile, error) {
	var profile domain.Profile
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&profile).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

func (r *profileRepo) Create(ctx context.Context, profile *domain.Profile) error {
	return r.db.WithContext(ctx).Create(profile).Error
}

func (r *profileRepo) Update(ctx context.Context, profile *domain.Profile) error {
	return r.db.WithContext(ctx).Save(profile).Error
}
