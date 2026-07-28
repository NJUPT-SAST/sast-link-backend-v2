package session

import (
	"context"
	"errors"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// Card returns the public display card of any non-deleted user.
//
// This is the only unauthenticated read in the service. It goes through a
// dedicated repository projection instead of reusing FindByID so that widening
// UserProfileDTO later cannot silently publish private columns.
func (s Service) Card(ctx context.Context, input CardInput) (*CardResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrUserNotFound, "用户不存在", nil)
	}
	card, err := s.Users.FindPublicCardByUserID(ctx, input.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrUserNotFound, "用户不存在", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询个人卡片失败", err)
	}
	dto := CardDTO{
		ID:        card.ID,
		Nickname:  card.Nickname,
		Intro:     card.Intro,
		Avatar:    card.Avatar,
		BlogURL:   card.BlogURL,
		GitHubURL: card.GitHubURL,
	}
	if card.Department != nil {
		department := string(*card.Department)
		dto.Department = &department
	}
	return &CardResult{Card: dto}, nil
}
