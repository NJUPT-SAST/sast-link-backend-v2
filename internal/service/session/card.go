package session

import (
	"context"
	"errors"
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// Card returns the public display card of any non-deleted user.
//
// It is the only unauthenticated read in the service; it goes through a
// dedicated repository projection so widening UserProfileDTO cannot publish
// private columns.
func (s Service) Card(ctx context.Context, input CardInput) (*CardResult, error) {
	// Throttled ahead of the ID check so probing for valid IDs is capped: the
	// rejection an invalid ID gets is itself the signal an enumerator wants.
	if clientIP := strings.TrimSpace(input.ClientIP); clientIP != "" {
		if err := s.checkEndpointLimit(ctx, s.CardLimiter, "card", "ip:"+clientIP); err != nil {
			return nil, err
		}
	}
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
