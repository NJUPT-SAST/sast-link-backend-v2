package repository

import (
	"context"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
)

// UserRepository defines the data access contract for the user table.
type UserRepository interface {
	FindByID(ctx context.Context, id int64) (*domain.User, error)
	FindByLoginEmail(ctx context.Context, email string) (*domain.User, error)
	FindByStudentID(ctx context.Context, studentID string) (*domain.User, error)
	Create(ctx context.Context, user *domain.User) error
	UpdatePassword(ctx context.Context, id int64, hash string) error
	UpdateState(ctx context.Context, id int64, state domain.UserState) error
}

// ProfileRepository defines the data access contract for the profile table.
type ProfileRepository interface {
	FindByUserID(ctx context.Context, userID int64) (*domain.Profile, error)
	Create(ctx context.Context, profile *domain.Profile) error
	Update(ctx context.Context, profile *domain.Profile) error
}

// OrganizeRepository defines the data access contract for the organize table.
type OrganizeRepository interface {
	FindAll(ctx context.Context) ([]domain.Organize, error)
	FindByID(ctx context.Context, id int16) (*domain.Organize, error)
}
