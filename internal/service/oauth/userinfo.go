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
// The caller has already been authenticated by the shared JWT middleware, so the
// token's validity, revocation and token_version are settled before this runs.
// What remains is scope filtering: a token without the profile scope must not
// yield profile claims even though the same account would supply them to a
// broader token.
func (s Service) UserInfo(ctx context.Context, input UserInfoInput) (*UserInfoResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "Access Token 无效", nil)
	}
	granted, err := scope.Normalize(input.Scopes)
	if err != nil {
		return nil, newError(ErrInvalidToken, "Access Token 的 scope 无效", err)
	}

	user, err := s.Users.FindByID(ctx, input.UserID)
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
	// sub always ships; everything else is gated, and the same gate as the ID
	// Token so the two endpoints cannot disagree about one token's claims.
	if slices.Contains(granted, scope.Profile) {
		result.Name = claims.Name
		result.Picture = claims.Picture
		result.PreferredUsername = claims.PreferredUsername
		result.Profile = claims.Profile
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
// carry. It does not filter by scope: the ID Token signer and UserInfo each apply
// the gate, so this stays a single description of where each claim comes from.
//
// The avatar and nickname live on the profile row, which is optional, so a
// missing card is not an error — it yields empty display claims that both callers
// then omit.
func (s Service) idTokenClaims(ctx context.Context, user *model.User, granted []string) (auth.IDTokenSubjectClaims, error) {
	claims := auth.IDTokenSubjectClaims{
		Name:      user.Name,
		Profile:   s.cardURL(user.ID),
		UpdatedAt: user.UpdatedAt,
		Email:     user.LoginEmail,
		// preferred_username falls back to the real name when no nickname is set, so
		// a relying party always has something displayable.
		PreferredUsername: user.Name,
	}
	// Only the profile scope needs the card lookup; skipping it otherwise keeps a
	// token limited to openid or email from touching the profile table at all.
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

// cardURL builds the public card URL used as the OIDC profile claim.
func (s Service) cardURL(userID int64) string {
	base := strings.TrimRight(strings.TrimSpace(s.CardBaseURL), "/")
	if base == "" {
		return ""
	}
	return base + "/" + userIDString(userID)
}
