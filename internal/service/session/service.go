package session

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

const (
	defaultAccessTTL         = time.Hour
	defaultRefreshTTL        = 30 * 24 * time.Hour
	loginCompensationTimeout = 5 * time.Second
)

var sessionScopes = scope.InternalSessionScopes

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
		return nil, newError(ErrInvalidInput, "invalid login input", nil)
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
		return nil, s.failLogin(ctx, nil, input, failureKey, ErrUnknownIdentifier, "login identifier not found", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find login user", err)
	}
	failureKey := loginFailureKey(user, identifier)
	if lockErr := s.checkLoginLock(ctx, failureKey); lockErr != nil {
		return nil, lockErr
	}
	if user.State == model.UserStateDeleted {
		if auditErr := s.audit(ctx, &user.ID, "login", "session", nil, false, errcode.CodeAccountDeleted, input.ClientIP, input.UserAgent, map[string]any{"method": loginMethod(user, identifier)}); auditErr != nil {
			slog.Error("audit deleted login failure", "user_id", user.ID, "error", auditErr)
		}
		return nil, newError(ErrUserDeleted, "user is deleted", nil)
	}
	if passwordErr := s.Passwords.VerifyPassword(input.Password, user.PasswordHash); passwordErr != nil {
		return nil, s.failLogin(ctx, user, input, failureKey, ErrPasswordInvalid, "password is invalid", passwordErr)
	}
	pair, err := s.issuePair(user, client, 0, "", sessionScopes)
	if err != nil {
		return nil, err
	}
	if err := s.Tokens.CreatePair(ctx, pair.access, pair.refresh); err != nil {
		return nil, newError(ErrInternal, "create token pair", err)
	}
	// From here the token pair is persisted. Any subsequent failure must
	// compensate by revoking the family so no half-issued session survives.
	compensate := func(message string, cause error) error {
		compensationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), loginCompensationTimeout)
		defer cancel()
		entries, revokeErr := s.Tokens.RevokeFamily(compensationCtx, pair.familyID, s.now())
		if revokeErr != nil {
			slog.Error("compensate revoke after login failure", "family_id", pair.familyID, "error", revokeErr)
		}
		s.deliverBlacklist(compensationCtx, entries, s.now())
		return newError(ErrInternal, message, cause)
	}
	if s.Failures != nil {
		if resetErr := s.Failures.Reset(ctx, failureKey); resetErr != nil {
			// A stale failure counter could lock the user on the next login.
			// Fail closed by revoking the issued pair.
			return nil, compensate("reset login failures", resetErr)
		}
	}
	if auditErr := s.audit(ctx, &user.ID, "login", "session", nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"method": loginMethod(user, identifier)}); auditErr != nil {
		return nil, compensate("audit login success", auditErr)
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
		return nil, newError(ErrInvalidInput, "invalid refresh input", nil)
	}
	tokenHash, err := s.RefreshTokens.HashRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, newError(ErrInvalidToken, "invalid refresh token", err)
	}
	current, err := s.Tokens.FindRefreshToken(ctx, tokenHash)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "invalid refresh token", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find refresh token", err)
	}
	if current.RevokedAt != nil {
		entries, revokeErr := s.Tokens.RevokeFamily(ctx, current.FamilyID, s.now())
		if revokeErr != nil {
			return nil, newError(ErrInternal, "revoke replayed refresh family", revokeErr)
		}
		s.deliverBlacklist(ctx, entries, s.now())
		return nil, newError(ErrInvalidToken, "invalid refresh token", nil)
	}
	if !current.ExpiresAt.After(s.now()) {
		return nil, newError(ErrInvalidToken, "invalid refresh token", nil)
	}
	client, err := s.findInternalClient(ctx)
	if err != nil {
		return nil, err
	}
	if current.ClientID != client.ID {
		return nil, newError(ErrInvalidToken, "refresh token client mismatch", nil)
	}
	user, err := s.Users.FindByID(ctx, current.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "invalid refresh token user", nil)
	}
	if err == nil && user.State == model.UserStateDeleted {
		return nil, newError(ErrUserDeleted, "user is deleted", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find refresh user", err)
	}

	pair, err := s.issuePair(user, client, current.Sequence+1, current.FamilyID, []string(current.Scopes))
	if err != nil {
		return nil, err
	}
	if rotateErr := s.Tokens.RotateRefreshToken(ctx, tokenHash, pair.access, pair.refresh); rotateErr != nil {
		if errors.Is(rotateErr, repository.ErrTokenReplay) || errors.Is(rotateErr, repository.ErrTokenExpired) || errors.Is(rotateErr, repository.ErrTokenFamilyRevoked) {
			// RotateRefreshToken revokes the family in the repository; re-invoke
			// RevokeFamily to obtain blacklist entries for synchronous Redis delivery.
			entries, revokeErr := s.Tokens.RevokeFamily(ctx, current.FamilyID, s.now())
			if revokeErr != nil {
				return nil, newError(ErrInternal, "revoke refresh family after rotation failure", revokeErr)
			}
			s.deliverBlacklist(ctx, entries, s.now())
			return nil, newError(ErrInvalidToken, "invalid refresh token", rotateErr)
		}
		return nil, newError(ErrInternal, "rotate refresh token", rotateErr)
	}
	return &RefreshResult{
		AccessToken:      pair.accessToken,
		RefreshToken:     pair.refreshToken,
		TokenType:        BearerTokenType,
		Scope:            pair.scopeClaim,
		AccessExpiresAt:  pair.access.ExpiresAt,
		RefreshExpiresAt: pair.refresh.ExpiresAt,
	}, nil
}

func (s Service) Logout(ctx context.Context, input LogoutInput) (*LogoutResult, error) {
	principalJTI := strings.TrimSpace(input.PrincipalJTI)
	if principalJTI == "" || input.PrincipalUserID <= 0 || strings.TrimSpace(input.RefreshToken) == "" {
		return nil, newError(ErrInvalidInput, "invalid logout input", nil)
	}
	access, err := s.Tokens.FindAccessTokenByJTI(ctx, principalJTI)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "access token metadata not found", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find access token", err)
	}
	tokenHash, err := s.RefreshTokens.HashRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, newError(ErrInvalidToken, "invalid refresh token", err)
	}
	refresh, err := s.Tokens.FindRefreshToken(ctx, tokenHash)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "refresh token metadata not found", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find refresh token", err)
	}
	now := s.now()
	if !access.ExpiresAt.After(now) || !refresh.ExpiresAt.After(now) {
		return nil, newError(ErrInvalidToken, "token is expired", nil)
	}
	if access.RevokedAt != nil || refresh.RevokedAt != nil {
		return nil, newError(ErrInvalidToken, "token is revoked", nil)
	}
	if access.FamilyID == nil || *access.FamilyID != refresh.FamilyID || access.UserID != input.PrincipalUserID || refresh.UserID != input.PrincipalUserID || access.ClientID != refresh.ClientID {
		return nil, newError(ErrInvalidToken, "token ownership mismatch", nil)
	}
	familyID := refresh.FamilyID
	entries, revokeErr := s.Tokens.RevokeFamily(ctx, familyID, now)
	if revokeErr != nil {
		return nil, newError(ErrInternal, "revoke token family", revokeErr)
	}
	s.deliverBlacklist(ctx, entries, now)
	if auditErr := s.audit(ctx, &input.PrincipalUserID, "logout", "session", &familyID, true, 0, input.ClientIP, input.UserAgent, map[string]any{}); auditErr != nil {
		slog.Error("audit logout", "family_id", familyID, "error", auditErr)
	}
	return &LogoutResult{BlacklistedJTI: principalJTI, FamilyID: familyID}, nil
}

func (s Service) Profile(ctx context.Context, input ProfileInput) (*ProfileResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidInput, "invalid profile input", nil)
	}
	user, err := s.Users.FindByID(ctx, input.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "invalid profile principal", nil)
	}
	if err == nil && user.State == model.UserStateDeleted {
		return nil, newError(ErrUserDeleted, "user is deleted", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find profile user", err)
	}
	return &ProfileResult{Profile: profileDTO(user)}, nil
}

func (s Service) checkEndpointLimit(ctx context.Context, endpoint, subject string) error {
	if s.Limiter == nil {
		return nil
	}
	result, err := s.Limiter.Allow(ctx, endpoint, subject)
	if err != nil {
		return newError(ErrInternal, "check endpoint limit", err)
	}
	if !result.Allowed {
		return withRetryAfter(newError(ErrRateLimited, "rate limited", nil), result.RetryAfter)
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
		return newError(ErrInternal, "check login lockout", err)
	}
	if locked {
		return withRetryAfter(newError(ErrLocked, "login locked", nil), retryAfter)
	}
	return nil
}

func (s Service) failLogin(ctx context.Context, user *model.User, input LoginInput, failureKey string, sentinel *Error, message string, cause error) error {
	locked := false
	lockTTL := time.Duration(0)
	if s.Failures != nil {
		result, err := s.Failures.RecordFailure(ctx, failureKey)
		if err != nil {
			return newError(ErrInternal, "record login failure", err)
		}
		locked = result.Locked
		lockTTL = result.TTL
	}
	if err := s.audit(ctx, loginUserID(user), "login", "session", nil, false, sentinel.Code, input.ClientIP, input.UserAgent, map[string]any{"method": loginMethod(user, input.Identifier)}); err != nil {
		slog.Error("audit login failure", "error", err)
	}
	if locked {
		return withRetryAfter(newError(ErrLocked, "login locked", nil), lockTTL)
	}
	return newError(sentinel, message, cause)
}

func (s Service) findInternalClient(ctx context.Context) (*model.OAuthClient, error) {
	if strings.TrimSpace(s.InternalClientID) == "" || s.Clients == nil {
		return nil, newError(ErrInternal, "internal client is not configured", nil)
	}
	client, err := s.Clients.FindActiveByClientID(ctx, strings.TrimSpace(s.InternalClientID))
	if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInvalidArgument) {
		return nil, newError(ErrInternal, "internal client is not available", err)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find internal client", err)
	}
	if client.ClientType != model.ClientTypeFirstParty || client.ClientSecretHash != nil {
		return nil, newError(ErrInternal, "internal client is not a public first-party client", nil)
	}
	if ok, err := scope.Equal([]string(client.Scopes), sessionScopes); err != nil || !ok {
		return nil, newError(ErrInternal, "internal client scopes must be canonical session scopes", err)
	}
	return client, nil
}
