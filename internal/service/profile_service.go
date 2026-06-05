package service

import (
	"context"
	"fmt"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/dto"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// ProfileService handles user profile queries and updates.
type ProfileService struct {
	userRepo    repository.UserRepository
	profileRepo repository.ProfileRepository
}

// NewProfileService creates a new ProfileService.
func NewProfileService(userRepo repository.UserRepository, profileRepo repository.ProfileRepository) *ProfileService {
	return &ProfileService{userRepo: userRepo, profileRepo: profileRepo}
}

// GetProfile returns the full user profile (user + profile + identities).
func (s *ProfileService) GetProfile(ctx context.Context, userID int64) (*dto.UserProfileData, error) {
	u, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get profile: %w", err)
	}
	if u == nil {
		return nil, domain.NewError(domain.ErrUserNotFound, "用户不存在")
	}

	p, err := s.profileRepo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get profile: %w", err)
	}

	result := &dto.UserProfileData{
		ID:          u.ID,
		Name:        u.Name,
		LoginEmail:  u.LoginEmail,
		Role:        string(u.Role),
		State:       string(u.State),
		EmailType:   string(u.EmailType),
		PhoneNumber: u.Phone,
		QQNumber:    u.QQNumber,
		StudentID:   u.StudentID,
		College:     string(u.College),
		Major:       u.Major,
		CreatedAt:   u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   u.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	if p != nil {
		result.Profile = &dto.ProfileData{
			Nickname:   p.Nickname,
			Department: string(p.Department),
			Intro:      p.Intro,
			Email:      p.Email,
			Avatar:     p.Avatar,
			BlogURL:    p.BlogURL,
			GitHubURL:  p.GitHubURL,
			CreatedAt:  p.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:  p.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	// TODO: populate identities when IdentityRepository is available
	result.Identities = []dto.IdentityData{}

	return result, nil
}

// UpdateProfile updates user and profile fields.
func (s *ProfileService) UpdateProfile(ctx context.Context, userID int64, req *dto.UpdateProfileRequest) error {
	u, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("update profile: %w", err)
	}
	if u == nil {
		return domain.NewError(domain.ErrUserNotFound, "用户不存在")
	}

	// Update user-level fields
	userChanged := false
	if req.Name != "" {
		u.Name = req.Name
		userChanged = true
	}
	if req.PhoneNumber != "" {
		u.Phone = req.PhoneNumber
		userChanged = true
	}
	if req.QQNumber != "" {
		u.QQNumber = req.QQNumber
		userChanged = true
	}
	if req.College != "" {
		c := domain.College(req.College)
		if isValidCollege(c) {
			u.College = c
			userChanged = true
		}
	}
	if req.Major != "" {
		u.Major = req.Major
		userChanged = true
	}
	if req.StudentID != "" {
		u.StudentID = req.StudentID
		userChanged = true
	}

	if userChanged {
		if err := s.userRepo.Update(ctx, u); err != nil {
			return fmt.Errorf("update profile: update user: %w", err)
		}
	}

	// Update profile-level fields
	p, err := s.profileRepo.FindByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("update profile: %w", err)
	}
	if p == nil {
		p = &domain.Profile{UserID: userID}
		if err := s.profileRepo.Create(ctx, p); err != nil {
			return fmt.Errorf("update profile: create profile: %w", err)
		}
		// GORM autoIncrement and autoCreateTime populate ID, CreatedAt, UpdatedAt on Create.
	}

	profileChanged := false
	if req.Nickname != "" {
		p.Nickname = req.Nickname
		profileChanged = true
	}
	if req.Department != "" {
		dep := domain.Department(req.Department)
		if !isValidDepartment(dep) {
			return domain.NewError(domain.ErrInvalidParams, "无效的部门值，可选值为 software 或 media")
		}
		p.Department = dep
		profileChanged = true
	}
	if req.Intro != "" {
		p.Intro = req.Intro
		profileChanged = true
	}
	if req.Email != "" {
		p.Email = req.Email
		profileChanged = true
	}
	if req.BlogURL != "" {
		p.BlogURL = req.BlogURL
		profileChanged = true
	}
	if req.GitHubURL != "" {
		p.GitHubURL = req.GitHubURL
		profileChanged = true
	}

	if profileChanged {
		if err := s.profileRepo.Update(ctx, p); err != nil {
			return fmt.Errorf("update profile: update profile: %w", err)
		}
	}

	return nil
}

// isValidDepartment checks whether a department value is valid.
func isValidDepartment(d domain.Department) bool {
	return d == domain.DepartmentSoftware || d == domain.DepartmentMedia
}
