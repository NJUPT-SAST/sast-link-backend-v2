package session

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

type issuedPair struct {
	accessToken  string
	refreshToken string
	scopeClaim   string
	familyID     string
	access       *model.OAuthAccessToken
	refresh      *model.OAuthRefreshToken
}

func (s Service) issuePair(user *model.User, client *model.OAuthClient, sequence int, familyID string, requestedScopes []string) (*issuedPair, error) {
	if user == nil || client == nil || s.JWT == nil || s.RefreshTokens == nil || s.Tokens == nil {
		return nil, serviceError(KindInternal, CodeInternal, "session dependencies are not configured", nil)
	}
	now := s.now()
	accessTTL := s.AccessTTL
	if accessTTL <= 0 {
		accessTTL = defaultAccessTTL
	}
	refreshTTL := s.RefreshTTL
	if refreshTTL <= 0 {
		refreshTTL = defaultRefreshTTL
	}
	scopes, err := scope.Normalize(requestedScopes)
	if err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "normalize token scopes", err)
	}
	scopeClaim, err := scope.Claim(scopes)
	if err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "encode session scopes", err)
	}
	if familyID == "" {
		familyID = uuid.NewString()
	}
	jti := uuid.NewString()
	accessToken, err := s.JWT.SignAccessToken(auth.TokenInput{
		Subject:      strconv.FormatInt(user.ID, 10),
		JTI:          jti,
		Role:         string(user.Role),
		State:        string(user.State),
		TokenVersion: user.TokenVersion,
		Scopes:       scopes,
		TTL:          accessTTL,
		NotBefore:    now,
	})
	if err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "sign access token", err)
	}
	refreshToken, err := s.RefreshTokens.NewRefreshToken()
	if err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "create refresh token", err)
	}
	refreshHash, err := s.RefreshTokens.HashRefreshToken(refreshToken)
	if err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "hash refresh token", err)
	}
	access := &model.OAuthAccessToken{
		TokenID:   jti,
		ClientID:  client.ID,
		UserID:    user.ID,
		FamilyID:  &familyID,
		Scopes:    model.StringArray(scopes),
		ExpiresAt: now.Add(accessTTL).UTC(),
		CreatedAt: now.UTC(),
	}
	refresh := &model.OAuthRefreshToken{
		TokenHash: refreshHash,
		FamilyID:  familyID,
		Sequence:  sequence,
		ClientID:  client.ID,
		UserID:    user.ID,
		Scopes:    model.StringArray(scopes),
		ExpiresAt: now.Add(refreshTTL).UTC(),
		CreatedAt: now.UTC(),
	}
	return &issuedPair{
		accessToken:  accessToken,
		refreshToken: refreshToken,
		scopeClaim:   scopeClaim,
		familyID:     familyID,
		access:       access,
		refresh:      refresh,
	}, nil
}

func (s Service) now() time.Time {
	clock := s.Clock
	if clock == nil {
		clock = systemClock{}
	}
	return clock.Now().UTC()
}

func normalizeIdentifier(identifier string) string {
	return strings.ToLower(strings.TrimSpace(identifier))
}

func loginLimitSubject(input LoginInput, identifier string) string {
	if strings.TrimSpace(input.ClientIP) != "" {
		return strings.TrimSpace(input.ClientIP)
	}
	return identifier
}

func loginFailureKey(user *model.User, identifier string) string {
	if user == nil {
		return "identifier:" + normalizeIdentifier(identifier)
	}
	return "user:" + strconv.FormatInt(user.ID, 10)
}

func loginMethod(user *model.User, identifier string) string {
	if user != nil && normalizeIdentifier(user.LoginEmail) != identifier {
		return "other_mail"
	}
	return "password"
}

func profileDTO(user *model.User) UserProfileDTO {
	dto := UserProfileDTO{
		ID:          user.ID,
		Name:        user.Name,
		LoginEmail:  user.LoginEmail,
		Role:        string(user.Role),
		State:       string(user.State),
		EmailType:   string(user.EmailType),
		PhoneNumber: user.PhoneNumber,
		QQNumber:    user.QQNumber,
		StudentID:   user.StudentID,
		College:     string(user.College),
		Major:       user.Major,
		Identities:  make([]IdentityDTO, 0, len(user.Identities)),
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}
	if user.Profile != nil {
		dto.Profile = &ProfileDetailDTO{
			Nickname:  user.Profile.Nickname,
			Intro:     user.Profile.Intro,
			Email:     user.Profile.Email,
			Avatar:    user.Profile.Avatar,
			BlogURL:   user.Profile.BlogURL,
			GitHubURL: user.Profile.GitHubURL,
			CreatedAt: user.Profile.CreatedAt,
			UpdatedAt: user.Profile.UpdatedAt,
		}
		if user.Profile.Department != nil {
			department := string(*user.Profile.Department)
			dto.Profile.Department = &department
		}
	}
	for _, identity := range user.Identities {
		dto.Identities = append(dto.Identities, IdentityDTO{
			ID:             identity.ID,
			Provider:       string(identity.Provider),
			ProviderID:     identity.ProviderID,
			IdentityData:   identity.IdentityData,
			TokenExpiresAt: identity.TokenExpiresAt,
			CreatedAt:      identity.CreatedAt,
			UpdatedAt:      identity.UpdatedAt,
		})
	}
	return dto
}

func (s Service) audit(ctx context.Context, userID *int64, action, resource string, resourceID *string, success bool, errCode int, clientIP, userAgent string, detail map[string]any) error {
	if s.Audit == nil {
		return nil
	}
	var detailValue model.JSONB
	if detail != nil {
		encoded, err := json.Marshal(detail)
		if err != nil {
			return fmt.Errorf("marshal audit detail: %w", err)
		}
		detailValue = model.JSONB(encoded)
	}
	var errCodePtr *int
	if errCode != 0 {
		errCodePtr = &errCode
	}
	var clientIPPtr *string
	if strings.TrimSpace(clientIP) != "" {
		clientIPPtr = &clientIP
	}
	var userAgentPtr *string
	if strings.TrimSpace(userAgent) != "" {
		userAgentPtr = &userAgent
	}
	successPtr := success
	return s.Audit.Create(ctx, &model.AuditLog{
		UserID:     userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Detail:     detailValue,
		ClientIP:   clientIPPtr,
		UserAgent:  userAgentPtr,
		Success:    &successPtr,
		ErrCode:    errCodePtr,
		CreatedAt:  s.now(),
	})
}
