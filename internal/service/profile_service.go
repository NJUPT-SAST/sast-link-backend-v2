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
	profileRepo repository.ProfileRepository
}

func NewProfileService(profileRepo repository.ProfileRepository) *ProfileService {
	return &ProfileService{profileRepo: profileRepo}
}

// GetProfile returns the profile for the given user.
func (s *ProfileService) GetProfile(ctx context.Context, userID int64) (*dto.ProfileResponse, error) {
	p, err := s.profileRepo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get profile: %w", err)
	}
	if p == nil {
		return nil, domain.NewError(domain.ErrProfileNotFound, "用户资料不存在")
	}
	return toProfileResponse(p), nil
}

// UpdateProfile updates fields on the user's profile.
func (s *ProfileService) UpdateProfile(ctx context.Context, userID int64, req dto.ChangeProfileRequest) error {
	p, err := s.profileRepo.FindByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("update profile: %w", err)
	}
	if p == nil {
		return domain.NewError(domain.ErrProfileNotFound, "用户资料不存在")
	}

	if req.Nickname != "" {
		p.Nickname = req.Nickname
	}
	if req.Department != "" {
		p.Department = domain.Department(req.Department)
	}
	if req.Intro != "" {
		p.Intro = req.Intro
	}
	if req.BlogURL != "" {
		p.BlogURL = req.BlogURL
	}
	if req.GitHubURL != "" {
		p.GitHubURL = req.GitHubURL
	}

	if err := s.profileRepo.Update(ctx, p); err != nil {
		return fmt.Errorf("update profile: %w", err)
	}
	return nil
}

func toProfileResponse(p *domain.Profile) *dto.ProfileResponse {
	return &dto.ProfileResponse{
		ID:         p.ID,
		UserID:     p.UserID,
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
