package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"gorm.io/gorm"
)

// UserRepository persists and retrieves user accounts.
type UserRepository struct {
	database *gorm.DB
}

// NewUser constructs a UserRepository backed by database.
func NewUser(database *gorm.DB) *UserRepository {
	return &UserRepository{database: database}
}

// CreateWithProfile creates a user and its profile atomically.
func (r *UserRepository) CreateWithProfile(
	ctx context.Context,
	user *model.User,
	profile *model.Profile,
) error {
	return r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Create(user).Error; err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		profile.UserID = user.ID
		if err := transaction.Create(profile).Error; err != nil {
			return fmt.Errorf("create profile: %w", err)
		}
		return nil
	})
}

// FindByLoginIdentifier finds a password-login user by login email or other email identity.
func (r *UserRepository) FindByLoginIdentifier(
	ctx context.Context,
	identifier string,
) (*model.User, error) {
	var user model.User
	database := r.database.WithContext(ctx).Preload("Profile").Preload("Identities")

	err := database.Where("login_email = ?", identifier).First(&user).Error
	if err == nil {
		return &user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("find user by login email: %w", err)
	}

	err = r.database.WithContext(ctx).
		Preload("Profile").
		Preload("Identities").
		Joins("JOIN identities ON identities.user_id = \"user\".id").
		Where("identities.provider = ? AND identities.provider_id = ?", model.LoginMethodOtherMail, identifier).
		First(&user).Error
	if err == nil {
		return &user, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find user by other email identity: %w", err)
}

// FindByID finds a user and its profile and identities by primary key.
func (r *UserRepository) FindByID(ctx context.Context, userID int64) (*model.User, error) {
	var user model.User
	err := r.database.WithContext(ctx).
		Preload("Profile").
		Preload("Identities").
		First(&user, userID).Error
	if err == nil {
		return &user, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find user by ID: %w", err)
}
