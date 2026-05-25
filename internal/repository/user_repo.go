package repository

import (
	"context"
	"errors"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
	"gorm.io/gorm"
)

type userRepo struct {
	db *gorm.DB
}

func NewUserRepo(db *gorm.DB) UserRepository {
	return &userRepo{db: db}
}

func (r *userRepo) FindByID(ctx context.Context, id int64) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil // Return nil if user not found, instead of an error
	}
	if err != nil {
		return nil, err // Return actual error if something really went wrong
	}
	return &user, nil // Return the found user
}

func (r *userRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepo) FindByUID(ctx context.Context, uid string) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).Where("uid = ?", uid).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepo) Create(ctx context.Context, user *domain.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *userRepo) UpdatePassword(ctx context.Context, id int64, hash string) error {
	return r.db.WithContext(ctx).Model(&domain.User{}).Where("id = ?", id).Update("password_hash", hash).Error
}

func (r *userRepo) SoftDelete(ctx context.Context, id int64) error {
	return r.db.WithContext(ctx).Model(&domain.User{}).Where("id = ?", id).Update("is_deleted", true).Error
}
