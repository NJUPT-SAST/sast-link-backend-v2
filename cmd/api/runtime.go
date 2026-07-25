package main

import (
	"context"
	"fmt"

	goredis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	sessionredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	sessionworker "github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session/worker"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/sessionhandler"
)

type sessionRuntime struct {
	Handler sessionhandler.Handler
	Auth    middleware.Authenticator
	Workers []backgroundWorker
}

func buildSessionRuntime(ctx context.Context, cfg *config.Config, database *gorm.DB, rdb *goredis.Client) (*sessionRuntime, error) {
	jwtManager, err := auth.NewJWTManager(auth.JWTConfig{
		Issuer:         cfg.JWTIssuer,
		Audience:       cfg.JWTAudience,
		ActiveKID:      cfg.JWTActiveKID,
		ActiveKeyPEM:   cfg.JWTSecretKey,
		PreviousKID:    cfg.JWTPreviousKID,
		PreviousKeyPEM: cfg.JWTSecretKeyPrev,
	})
	if err != nil {
		return nil, fmt.Errorf("construct JWT manager: %w", err)
	}
	refreshManager, err := auth.NewRefreshTokenManager(cfg.RefreshTokenHMACSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("construct refresh token manager: %w", err)
	}

	users := repository.NewUser(database)
	clients := repository.NewOAuthClient(database)
	if err := validateInternalClient(ctx, clients, cfg.InternalOAuthClientID); err != nil {
		return nil, err
	}
	tokens := repository.NewToken(database)
	outbox := repository.NewTokenBlacklistOutbox(database)
	audit := repository.NewAuditLog(database)

	keys := internalredis.NewKeys(cfg.RedisKeyPrefix)
	store := internalredis.Store{Client: rdb, Keys: keys}
	blacklist := sessionredis.BlacklistStore{Store: store}
	limiter := sessionredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitLoginRPM,
			Window: cfg.RateLimitLoginWindow,
		},
	}
	failures := sessionredis.LoginFailureStore{Store: store, Limit: cfg.LoginFailureLimit, Window: cfg.LoginFailureWindow}

	service := session.Service{
		Users:            users,
		Clients:          clients,
		Tokens:           tokens,
		Audit:            audit,
		Limiter:          limiter,
		Failures:         failures,
		Blacklist:        blacklist,
		InternalClientID: cfg.InternalOAuthClientID,
		JWT:              jwtManager,
		RefreshTokens:    refreshManager,
		Passwords:        auth.PasswordHasher{},
		AccessTTL:        cfg.JWTAccessTokenExpiry,
		RefreshTTL:       cfg.JWTRefreshTokenExpiry,
	}
	authenticator := middleware.Authenticator{
		JWT:       jwtManager,
		Blacklist: blacklist,
		Tokens:    tokens,
	}
	return &sessionRuntime{
		Handler: sessionhandler.Handler{Service: service},
		Auth:    authenticator,
		Workers: []backgroundWorker{sessionworker.TokenBlacklist{Outbox: outbox, Blacklist: blacklist}},
	}, nil
}

func validateInternalClient(ctx context.Context, clients *repository.OAuthClientRepository, clientID string) error {
	client, err := clients.FindActiveByClientID(ctx, clientID)
	if err != nil {
		return fmt.Errorf("validate internal OAuth client: %w", err)
	}
	return validateInternalClientModel(client)
}

func validateInternalClientModel(client *model.OAuthClient) error {
	if client == nil {
		return fmt.Errorf("validate internal OAuth client: client is nil")
	}
	if client.ClientType != model.ClientTypeFirstParty || client.ClientSecretHash != nil {
		return fmt.Errorf("validate internal OAuth client: client must be first-party public")
	}
	if ok, err := scope.Equal([]string(client.Scopes), scope.InternalSessionScopes); err != nil || !ok {
		return fmt.Errorf("validate internal OAuth client: scopes must be canonical %q", scope.InternalSessionScopes)
	}
	return nil
}
