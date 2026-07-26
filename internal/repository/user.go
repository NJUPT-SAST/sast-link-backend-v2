package repository

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// UserRepository persists and retrieves user accounts.
type UserRepository struct {
	database *gorm.DB
}

// UserAuthState is the minimal user state needed for token authentication checks.
type UserAuthState struct {
	ID           int64
	State        model.UserState
	TokenVersion int
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
	if user == nil {
		return fmt.Errorf("%w: user is nil", ErrInvalidArgument)
	}
	if profile == nil {
		return fmt.Errorf("%w: profile is nil", ErrInvalidArgument)
	}

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

// FindByLoginEmail finds a user by login email only (excludes other-mail identities).
func (r *UserRepository) FindByLoginEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User
	err := r.database.WithContext(ctx).
		Preload("Profile").
		Preload("Identities").
		Where("login_email = ?", email).
		First(&user).Error
	if err == nil {
		return &user, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find user by login email: %w", err)
}

// UpdatePasswordAndBumpTokenVersion atomically replaces the password hash and
// increments token_version, so every previously issued access token is rejected
// by the version mismatch even before family revocation is delivered.
func (r *UserRepository) UpdatePasswordAndBumpTokenVersion(ctx context.Context, userID int64, passwordHash string) error {
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Model(&model.User{}).
			Where("id = ?", userID).
			Update("password", passwordHash).Error; err != nil {
			return fmt.Errorf("update password: %w", err)
		}
		if err := transaction.Model(&model.User{}).
			Where("id = ?", userID).
			UpdateColumn("token_version", gorm.Expr("token_version + 1")).Error; err != nil {
			return fmt.Errorf("increment token version: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("update password and bump token version: %w", err)
	}
	return nil
}

// ExistsByLoginEmail reports whether a user with the given login email exists.
func (r *UserRepository) ExistsByLoginEmail(ctx context.Context, email string) (bool, error) {
	var count int64
	if err := r.database.WithContext(ctx).Model(&model.User{}).Where("login_email = ?", email).Count(&count).Error; err != nil {
		return false, fmt.Errorf("count user by login email: %w", err)
	}
	return count > 0, nil
}

// ExistsByStudentID reports whether a user with the given student ID exists.
func (r *UserRepository) ExistsByStudentID(ctx context.Context, studentID string) (bool, error) {
	var count int64
	if err := r.database.WithContext(ctx).Model(&model.User{}).Where("student_id = ?", studentID).Count(&count).Error; err != nil {
		return false, fmt.Errorf("count user by student id: %w", err)
	}
	return count > 0, nil
}

// FindAuthStateByID finds the minimal user state required to authenticate tokens.
func (r *UserRepository) FindAuthStateByID(ctx context.Context, userID int64) (*UserAuthState, error) {
	var state UserAuthState
	err := r.database.WithContext(ctx).
		Model(&model.User{}).
		Select("id", "state", "token_version").
		First(&state, userID).Error
	if err == nil {
		return &state, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find user auth state by ID: %w", err)
}
