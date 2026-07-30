package main

import (
	"context"
	"fmt"

	goredis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	oauthredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/oauth"
	sessionredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/mailer"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminclient"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminuser"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	sessionworker "github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session/worker"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/adminhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/oauthhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/sessionhandler"
)

type sessionRuntime struct {
	Handler sessionhandler.Handler
	OAuth   oauthhandler.Handler
	Admin   adminhandler.Handler
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
	identities := repository.NewIdentity(database)

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
	emailLimiter := sessionredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitSendEmailRPM,
			Window: cfg.RateLimitSendEmailWindow,
		},
	}
	emailIPLimiter := sessionredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitSendEmailIPRPM,
			Window: cfg.RateLimitSendEmailWindow,
		},
	}
	failures := sessionredis.LoginFailureStore{Store: store, Limit: cfg.LoginFailureLimit, Window: cfg.LoginFailureWindow}
	bindTickets := sessionredis.BindTicketStore{Store: store}
	unbindLimiter := sessionredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitUnbindRPM,
			Window: cfg.RateLimitUnbindWindow,
		},
	}
	emailer := mailer.New(mailer.Config{
		Host:          cfg.SMTPHost,
		Port:          cfg.SMTPPort,
		Username:      cfg.SMTPUser,
		Password:      cfg.SMTPPass,
		From:          cfg.SMTPFrom,
		UseTLS:        cfg.SMTPUseTLS,
		MaxConcurrent: cfg.SMTPMaxConcurrent,
	})
	forgotPasswords := sessionworker.NewForgotPassword(users, store, emailer, audit)

	service := session.Service{
		Users:            users,
		Clients:          clients,
		Tokens:           tokens,
		Audit:            audit,
		Identities:       identities,
		Limiter:          limiter,
		EmailLimiter:     emailLimiter,
		EmailIPLimiter:   emailIPLimiter,
		Failures:         failures,
		Blacklist:        blacklist,
		Mailer:           emailer,
		VerificationCode: store,
		RegisterTicket:   store,
		BindTicket:       bindTickets,
		UnbindLimiter:    unbindLimiter,
		ForgotPasswords:  forgotPasswords,
		InternalClientID: cfg.InternalOAuthClientID,
		JWT:              jwtManager,
		RefreshTokens:    refreshManager,
		Passwords:        auth.PasswordHasher{Semaphore: make(chan struct{}, cfg.PasswordHashMaxConcurrent)},
		AccessTTL:        cfg.JWTAccessTokenExpiry,
		RefreshTTL:       cfg.JWTRefreshTokenExpiry,
	}
	authenticator := middleware.Authenticator{
		JWT:       jwtManager,
		Blacklist: blacklist,
		Tokens:    tokens,
		// Pins the internal API to the built-in client, so a third-party OAuth access
		// token cannot be used as a session credential.
		InternalClientID: cfg.InternalOAuthClientID,
	}

	authorizeLimiter := oauthredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitAuthorizeRPM,
			Window: cfg.RateLimitAuthorizeWindow,
		},
	}
	tokenLimiter := oauthredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitTokenRPM,
			Window: cfg.RateLimitTokenWindow,
		},
	}
	oauthService := oauth.Service{
		Users:            users,
		Clients:          clients,
		Authorizations:   repository.NewOAuthAuthorization(database),
		Tokens:           tokens,
		Audit:            audit,
		Profiles:         users,
		Requests:         oauthredis.AuthorizeRequestStore{Store: store},
		Blacklist:        oauthredis.BlacklistStore{Store: store},
		AuthorizeLimiter: authorizeLimiter,
		TokenLimiter:     tokenLimiter,
		JWT:              jwtManager,
		RefreshTokens:    refreshManager,
		AccessTTL:        cfg.JWTAccessTokenExpiry,
		RefreshTTL:       cfg.JWTRefreshTokenExpiry,
		CodeTTL:          cfg.OAuthCodeTTL,
		RequestTTL:       cfg.OAuthAuthorizeRequestTTL,
		CardBaseURL:      cfg.OAuthCardBaseURL,
		// The discovery document's issuer must equal the iss claim of every issued
		// token, so both read the same setting.
		Issuer: cfg.JWTIssuer,
	}

	adminUserService := adminuser.Service{
		Users:     users,
		Audit:     audit,
		Blacklist: oauthredis.BlacklistStore{Store: store},
	}

	adminClientService := adminclient.Service{
		Clients:   clients,
		Blacklist: oauthredis.BlacklistStore{Store: store},
		Audit:     audit,
		// Default random source and hashing; no work factor is bought for a 32-byte
		// random secret, see auth.ClientSecretHasher.
		Secrets: auth.ClientSecretHasher{},
		// The same client the internal API pins its azp gate to. Disabling it would
		// lock every user out of login with no in-band way back.
		ProtectedClientID: cfg.InternalOAuthClientID,
	}

	return &sessionRuntime{
		Handler: sessionhandler.Handler{Service: service},
		OAuth: oauthhandler.Handler{
			Service:    oauthService,
			Auth:       authenticator,
			ConsentURL: cfg.OAuthConsentURL,
		},
		Admin: adminhandler.Handler{
			Clients:   adminClientService,
			Users:     adminUserService,
			AuditLogs: adminUserService,
		},
		Auth: authenticator,
		Workers: []backgroundWorker{
			sessionworker.TokenBlacklist{Outbox: outbox, Blacklist: blacklist},
			forgotPasswords,
		},
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
