package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

const (
	defaultAccessTTL  = time.Hour
	defaultRefreshTTL = 30 * 24 * time.Hour
)

var sessionScopes = []string{scope.OpenID, scope.Profile, scope.Email}

type Service struct {
	Users            UserRepository
	Clients          ClientRepository
	Tokens           TokenRepository
	Audit            AuditRepository
	Limiter          EndpointLimiter
	Failures         LoginFailureStore
	Blacklist        TokenBlacklist
	InternalClientID string
	JWT              *auth.JWTManager
	RefreshTokens    *auth.RefreshTokenManager
	Passwords        auth.PasswordHasher
	Clock            Clock
	AccessTTL        time.Duration
	RefreshTTL       time.Duration
}

func (s Service) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	identifier := normalizeIdentifier(input.Identifier)
	if identifier == "" || input.Password == "" {
		return nil, serviceError(KindInvalidInput, CodeInvalidInput, "invalid login input", nil)
	}
	if err := s.checkEndpointLimit(ctx, "login", loginLimitSubject(input, identifier)); err != nil {
		return nil, err
	}
	client, err := s.findInternalClient(ctx)
	if err != nil {
		return nil, err
	}
	user, err := s.Users.FindByLoginIdentifier(ctx, identifier)
	if errors.Is(err, repository.ErrNotFound) {
		failureKey := loginFailureKey(nil, identifier)
		if lockErr := s.checkLoginLock(ctx, failureKey); lockErr != nil {
			return nil, lockErr
		}
		return nil, s.failLogin(ctx, nil, input, failureKey, CodeUnknownIdentifier, KindUnknownIdentifier, "login identifier not found", nil)
	}
	if err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "find login user", err)
	}
	failureKey := loginFailureKey(user, identifier)
	if lockErr := s.checkLoginLock(ctx, failureKey); lockErr != nil {
		return nil, lockErr
	}
	if user.State == model.UserStateDeleted {
		if auditErr := s.audit(ctx, &user.ID, "login", "session", nil, false, CodeUserDeleted, input.ClientIP, input.UserAgent, map[string]any{"method": loginMethod(user, identifier)}); auditErr != nil {
			return nil, serviceError(KindInternal, CodeInternal, "audit deleted login failure", auditErr)
		}
		return nil, serviceError(KindUserDeleted, CodeUserDeleted, "user is deleted", nil)
	}
	if passwordErr := s.Passwords.VerifyPassword(input.Password, user.PasswordHash); passwordErr != nil {
		return nil, s.failLogin(ctx, &user.ID, input, failureKey, CodePasswordInvalid, KindPasswordInvalid, "password is invalid", passwordErr)
	}
	if s.Failures != nil {
		if resetErr := s.Failures.Reset(ctx, failureKey); resetErr != nil {
			return nil, serviceError(KindInternal, CodeInternal, "reset login failures", resetErr)
		}
	}

	pair, err := s.issuePair(user, client, 0, "", sessionScopes)
	if err != nil {
		return nil, err
	}
	if err := s.Tokens.CreatePair(ctx, pair.access, pair.refresh); err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "create token pair", err)
	}
	if auditErr := s.audit(ctx, &user.ID, "login", "session", nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"method": loginMethod(user, identifier)}); auditErr != nil {
		entries, _ := s.Tokens.RevokeFamily(ctx, pair.familyID, s.now())
		s.deliverBlacklist(ctx, entries, s.now())
		return nil, serviceError(KindInternal, CodeInternal, "audit login success", auditErr)
	}
	return &LoginResult{
		AccessToken:      pair.accessToken,
		RefreshToken:     pair.refreshToken,
		TokenType:        BearerTokenType,
		Scope:            pair.scopeClaim,
		AccessExpiresAt:  pair.access.ExpiresAt,
		RefreshExpiresAt: pair.refresh.ExpiresAt,
		Profile:          profileDTO(user),
	}, nil
}

func (s Service) Refresh(ctx context.Context, input RefreshInput) (*RefreshResult, error) {
	if strings.TrimSpace(input.RefreshToken) == "" {
		return nil, serviceError(KindInvalidInput, CodeInvalidInput, "invalid refresh input", nil)
	}
	tokenHash, err := s.RefreshTokens.HashRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, serviceError(KindInvalidToken, CodeInvalidToken, "invalid refresh token", err)
	}
	current, err := s.Tokens.FindRefreshToken(ctx, tokenHash)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, serviceError(KindInvalidToken, CodeInvalidToken, "invalid refresh token", nil)
	}
	if err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "find refresh token", err)
	}
	if current.RevokedAt != nil {
		entries, revokeErr := s.Tokens.RevokeFamily(ctx, current.FamilyID, s.now())
		if revokeErr != nil {
			return nil, serviceError(KindInternal, CodeInternal, "revoke replayed refresh family", revokeErr)
		}
		s.deliverBlacklist(ctx, entries, s.now())
		return nil, serviceError(KindInvalidToken, CodeInvalidToken, "invalid refresh token", nil)
	}
	if !current.ExpiresAt.After(s.now()) {
		return nil, serviceError(KindInvalidToken, CodeInvalidToken, "invalid refresh token", nil)
	}
	client, err := s.findInternalClient(ctx)
	if err != nil {
		return nil, err
	}
	if current.ClientID != client.ID {
		return nil, serviceError(KindInvalidToken, CodeInvalidToken, "refresh token client mismatch", nil)
	}
	user, err := s.Users.FindByID(ctx, current.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, serviceError(KindInvalidToken, CodeInvalidToken, "invalid refresh token user", nil)
	}
	if err == nil && user.State == model.UserStateDeleted {
		return nil, serviceError(KindUserDeleted, CodeUserDeleted, "user is deleted", nil)
	}
	if err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "find refresh user", err)
	}

	pair, err := s.issuePair(user, client, current.Sequence+1, current.FamilyID, []string(current.Scopes))
	if err != nil {
		return nil, err
	}
	if rotateErr := s.Tokens.RotateRefreshToken(ctx, tokenHash, pair.access, pair.refresh); rotateErr != nil {
		if errors.Is(rotateErr, repository.ErrTokenReplay) || errors.Is(rotateErr, repository.ErrTokenExpired) || errors.Is(rotateErr, repository.ErrTokenFamilyRevoked) {
			return nil, serviceError(KindInvalidToken, CodeInvalidToken, "invalid refresh token", rotateErr)
		}
		return nil, serviceError(KindInternal, CodeInternal, "rotate refresh token", rotateErr)
	}
	claim, err := scope.Claim([]string(pair.refresh.Scopes))
	if err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "encode refresh scopes", err)
	}
	return &RefreshResult{
		AccessToken:      pair.accessToken,
		RefreshToken:     pair.refreshToken,
		TokenType:        BearerTokenType,
		Scope:            claim,
		AccessExpiresAt:  pair.access.ExpiresAt,
		RefreshExpiresAt: pair.refresh.ExpiresAt,
	}, nil
}

func (s Service) Logout(ctx context.Context, input LogoutInput) (*LogoutResult, error) {
	principalJTI := strings.TrimSpace(input.PrincipalJTI)
	if principalJTI == "" || input.PrincipalUserID <= 0 || strings.TrimSpace(input.RefreshToken) == "" {
		return nil, serviceError(KindInvalidInput, CodeInvalidInput, "invalid logout input", nil)
	}
	access, err := s.Tokens.FindAccessTokenByJTI(ctx, principalJTI)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, serviceError(KindInvalidToken, CodeInvalidToken, "access token metadata not found", nil)
	}
	if err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "find access token", err)
	}
	tokenHash, err := s.RefreshTokens.HashRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, serviceError(KindInvalidToken, CodeInvalidToken, "invalid refresh token", err)
	}
	refresh, err := s.Tokens.FindRefreshToken(ctx, tokenHash)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, serviceError(KindInvalidToken, CodeInvalidToken, "refresh token metadata not found", nil)
	}
	if err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "find refresh token", err)
	}
	now := s.now()
	if !access.ExpiresAt.After(now) || !refresh.ExpiresAt.After(now) {
		return nil, serviceError(KindInvalidToken, CodeInvalidToken, "token is expired", nil)
	}
	if access.FamilyID == nil || *access.FamilyID != refresh.FamilyID || access.UserID != input.PrincipalUserID || refresh.UserID != input.PrincipalUserID || access.ClientID != refresh.ClientID {
		return nil, serviceError(KindInvalidToken, CodeInvalidToken, "token ownership mismatch", nil)
	}
	familyID := refresh.FamilyID
	entries, revokeErr := s.Tokens.RevokeFamily(ctx, familyID, now)
	if revokeErr != nil {
		return nil, serviceError(KindInternal, CodeInternal, "revoke token family", revokeErr)
	}
	s.deliverBlacklist(ctx, entries, now)
	if auditErr := s.audit(ctx, &input.PrincipalUserID, "logout", "session", &familyID, true, 0, input.ClientIP, input.UserAgent, map[string]any{}); auditErr != nil {
		slog.Error("audit logout", "family_id", familyID, "error", auditErr)
	}
	return &LogoutResult{BlacklistedJTI: principalJTI, FamilyID: familyID}, nil
}

func (s Service) Profile(ctx context.Context, input ProfileInput) (*ProfileResult, error) {
	if input.UserID <= 0 {
		return nil, serviceError(KindInvalidInput, CodeInvalidInput, "invalid profile input", nil)
	}
	user, err := s.Users.FindByID(ctx, input.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, serviceError(KindInvalidToken, CodeInvalidToken, "invalid profile principal", nil)
	}
	if err == nil && user.State == model.UserStateDeleted {
		return nil, serviceError(KindUserDeleted, CodeUserDeleted, "user is deleted", nil)
	}
	if err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "find profile user", err)
	}
	return &ProfileResult{Profile: profileDTO(user)}, nil
}

func (s Service) checkEndpointLimit(ctx context.Context, endpoint, subject string) error {
	if s.Limiter == nil {
		return nil
	}
	result, err := s.Limiter.Allow(ctx, endpoint, subject)
	if err != nil {
		return serviceError(KindInternal, CodeInternal, "check endpoint limit", err)
	}
	if !result.Allowed {
		return serviceError(KindRateLimited, CodeRateLimited, fmt.Sprintf("rate limited for %s", result.RetryAfter), nil)
	}
	return nil
}

func (s Service) deliverBlacklist(ctx context.Context, entries []model.BlacklistEntry, now time.Time) {
	if s.Blacklist == nil {
		return
	}
	for _, entry := range entries {
		ttl := entry.ExpiresAt.Sub(now)
		if ttl <= 0 || strings.TrimSpace(entry.TokenID) == "" {
			continue
		}
		if err := s.Blacklist.BlacklistJTI(ctx, entry.TokenID, ttl); err != nil {
			slog.Error("deliver token blacklist entry", "token_id", entry.TokenID, "error", err)
		}
	}
}

func (s Service) checkLoginLock(ctx context.Context, key string) error {
	if s.Failures == nil {
		return nil
	}
	locked, retryAfter, err := s.Failures.IsLocked(ctx, key)
	if err != nil {
		return serviceError(KindInternal, CodeInternal, "check login lockout", err)
	}
	if locked {
		return serviceError(KindLocked, CodeRateLimited, fmt.Sprintf("login locked for %s", retryAfter), nil)
	}
	return nil
}

func (s Service) failLogin(ctx context.Context, userID *int64, input LoginInput, failureKey string, code int, kind Kind, message string, cause error) error {
	locked := false
	lockTTL := time.Duration(0)
	if s.Failures != nil {
		result, err := s.Failures.RecordFailure(ctx, failureKey)
		if err != nil {
			return serviceError(KindInternal, CodeInternal, "record login failure", err)
		}
		locked = result.Locked
		lockTTL = result.TTL
	}
	if err := s.audit(ctx, userID, "login", "session", nil, false, code, input.ClientIP, input.UserAgent, map[string]any{"method": "password"}); err != nil {
		return serviceError(KindInternal, CodeInternal, "audit login failure", err)
	}
	if locked {
		return serviceError(KindLocked, CodeRateLimited, fmt.Sprintf("login locked for %s", lockTTL), nil)
	}
	return serviceError(kind, code, message, cause)
}

func (s Service) findInternalClient(ctx context.Context) (*model.OAuthClient, error) {
	if strings.TrimSpace(s.InternalClientID) == "" || s.Clients == nil {
		return nil, serviceError(KindInternal, CodeInternal, "internal client is not configured", nil)
	}
	client, err := s.Clients.FindActiveByClientID(ctx, strings.TrimSpace(s.InternalClientID))
	if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInvalidArgument) {
		return nil, serviceError(KindInternal, CodeInternal, "internal client is not available", err)
	}
	if err != nil {
		return nil, serviceError(KindInternal, CodeInternal, "find internal client", err)
	}
	if client.ClientType != model.ClientTypeFirstParty || client.ClientSecretHash != nil {
		return nil, serviceError(KindInternal, CodeInternal, "internal client is not a public first-party client", nil)
	}
	if ok, err := scope.ContainsAll([]string(client.Scopes), sessionScopes); err != nil || !ok {
		return nil, serviceError(KindInternal, CodeInternal, "internal client missing session scopes", err)
	}
	return client, nil
}
