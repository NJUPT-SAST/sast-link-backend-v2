package oauth

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

// UserInfo returns the OIDC claims a token's scopes permit.
//
// The shared JWT middleware has already settled the token's validity, revocation
// and token_version; all that remains is scope filtering, so a token without the
// profile scope cannot yield profile claims.
func (s Service) UserInfo(ctx context.Context, input UserInfoInput) (*UserInfoResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "Access Token 无效", nil)
	}
	normalized, err := scope.Normalize(input.Scopes)
	if err != nil {
		return nil, newError(ErrInvalidToken, "Access Token 的 scope 无效", err)
	}
	// Admin scopes grant no claim, so "openid admin:read" answers identically to
	// "openid": sub alone.
	granted := scope.ClaimScopes(normalized)

	user, err := s.Users.FindAuthUserByID(ctx, input.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "Access Token 无效", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询用户失败", err)
	}
	if user.State == model.UserStateDeleted {
		return nil, newError(ErrInvalidToken, "账号已注销", nil)
	}

	claims, err := s.idTokenClaims(ctx, user, granted)
	if err != nil {
		return nil, err
	}
	result := &UserInfoResult{Subject: userIDString(user.ID)}
	// sub always ships; the rest is gated by the same gate as the ID Token so the
	// two endpoints cannot disagree about one token's claims.
	if slices.Contains(granted, scope.Profile) {
		result.Name = claims.Name
		result.Picture = claims.Picture
		result.PreferredUsername = claims.PreferredUsername
		result.Role = claims.Role
		if !claims.UpdatedAt.IsZero() {
			result.UpdatedAt = claims.UpdatedAt.UTC().Unix()
		}
	}
	if slices.Contains(granted, scope.Email) {
		result.Email = claims.Email
		verified := true
		result.EmailVerified = &verified
	}
	return result, nil
}

// idTokenClaims collects every claim an ID Token or UserInfo response could
// carry, without filtering by scope — the signer and UserInfo each apply the gate.
//
// The avatar and nickname live on the optional profile row, so a missing card is
// not an error; it yields empty display claims the callers omit.
func (s Service) idTokenClaims(ctx context.Context, user *model.User, granted []string) (auth.IDTokenSubjectClaims, error) {
	claims := auth.IDTokenSubjectClaims{
		Name: user.Name,
		// Role read from the database now, not from the requesting token's signing-time
		// snapshot that would outlive a demotion.
		Role:      string(user.Role),
		UpdatedAt: user.UpdatedAt,
		Email:     user.LoginEmail,
		// preferred_username falls back to the real name when no nickname is set.
		PreferredUsername: user.Name,
	}
	// Only the profile scope needs the card lookup; other tokens never touch the
	// profile table.
	if !slices.Contains(granted, scope.Profile) {
		return claims, nil
	}
	if s.Profiles == nil {
		return claims, nil
	}
	card, err := s.Profiles.FindPublicCardByUserID(ctx, user.ID)
	if errors.Is(err, repository.ErrNotFound) {
		return claims, nil
	}
	if err != nil {
		return auth.IDTokenSubjectClaims{}, newError(ErrInternal, "查询用户展示资料失败", err)
	}
	if card.Avatar != nil {
		claims.Picture = *card.Avatar
	}
	if card.Nickname != nil && strings.TrimSpace(*card.Nickname) != "" {
		claims.PreferredUsername = *card.Nickname
	}
	return claims, nil
}
