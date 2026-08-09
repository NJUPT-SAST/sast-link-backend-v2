package main

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	cosadapter "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/cos"
	oauthredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/oauth"
	oauthloginredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/oauthlogin"
	sessionredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/mailer"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/objectstore"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/provider"
	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminclient"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminuser"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauthlogin"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	sessionworker "github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session/worker"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/tokenissue"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/adminhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/oauthhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/oauthloginhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/sessionhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/worker"
)

type sessionRuntime struct {
	Handler    sessionhandler.Handler
	OAuth      oauthhandler.Handler
	OAuthLogin oauthloginhandler.Handler
	Admin      adminhandler.Handler
	Auth       middleware.Authenticator
	Workers    []backgroundWorker
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
	// The tombstone must outlive the longest in-flight request. Size it from
	// the server WriteTimeout plus a small margin so a configuration change to
	// either value cannot silently reopen the stale-refill race window.
	store := internalredis.Store{
		Client:                rdb,
		Keys:                  keys,
		AuthStateTombstoneTTL: ServerWriteTimeout + 5*time.Second,
	}
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
	oauthLoginStates := oauthloginredis.StateStore{Store: store}
	oauthRegistrations := oauthloginredis.RegistrationStateStore{Store: store}
	oauthLoginCodes := oauthloginredis.LoginCodeStore{Store: store}
	unbindLimiter := sessionredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitUnbindRPM,
			Window: cfg.RateLimitUnbindWindow,
		},
	}
	registerLimiter := sessionredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitRegisterAttempts,
			Window: cfg.RateLimitRegisterWindow,
		},
	}
	cardLimiter := sessionredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitCardRPM,
			Window: cfg.RateLimitCardWindow,
		},
	}
	refreshLimiter := sessionredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitRefreshRPM,
			Window: cfg.RateLimitRefreshWindow,
		},
	}
	avatarLimiter := sessionredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitUploadAvatarRPM,
			Window: cfg.RateLimitUploadAvatarWindow,
		},
	}
	deviceLimiter := sessionredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitDeviceRPM,
			Window: cfg.RateLimitDeviceWindow,
		},
	}
	// Object storage is optional: an unconfigured deployment keeps every other
	// endpoint and answers 50002 on PUT /user/avatar. When configured, the COS
	// client also carries the image review (fail-closed by default).
	var avatarStore objectstore.ObjectStore
	var avatarAuditor objectstore.AvatarAuditor
	if cfg.StorageConfigured() {
		storage, storageErr := cosadapter.New(cosadapter.Config{
			Endpoint:  cfg.StorageEndpoint,
			Region:    cfg.StorageRegion,
			Bucket:    cfg.StorageBucket,
			AccessKey: cfg.StorageAccessKey,
			SecretKey: cfg.StorageSecretKey,
			BaseURL:   cfg.StorageBaseURL,
		})
		if storageErr != nil {
			return nil, fmt.Errorf("construct object storage client: %w", storageErr)
		}
		avatarStore = storage
		if cfg.StorageAuditEnabled {
			avatarAuditor = storage
		}
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
		// Reads the key oauthloginredis.RegistrationStateStore writes, so a
		// callback's parked identity can be redeemed by POST /auth/register.
		OAuthRegistration: sessionredis.OAuthRegistrationStore{Store: store},
		UnbindLimiter:     unbindLimiter,
		RegisterLimiter:   registerLimiter,
		CardLimiter:       cardLimiter,
		AvatarLimiter:     avatarLimiter,
		RefreshLimiter:    refreshLimiter,
		AvatarStore:       avatarStore,
		AvatarAuditor:     avatarAuditor,
		Devices:           sessionredis.DeviceStore{Store: store},
		DeviceLimiter:     deviceLimiter,
		ForgotPasswords:   forgotPasswords,
		InternalClientID:  cfg.InternalOAuthClientID,
		JWT:               jwtManager,
		RefreshTokens:     refreshManager,
		Passwords: auth.PasswordHasher{
			Semaphore:     make(chan struct{}, cfg.Argon2Concurrency),
			Argon2Time:    cfg.Argon2Time,
			Argon2Memory:  cfg.Argon2Memory,
			Argon2Threads: cfg.Argon2Threads,
		},
		AccessTTL:  cfg.JWTAccessTokenExpiry,
		RefreshTTL: cfg.JWTRefreshTokenExpiry,
	}
	authenticator := middleware.Authenticator{
		JWT: jwtManager,
		// The auth-state cache replaces the old per-request blacklist GET + DB query:
		// authenticated requests serve their revocation/role state from Redis for a
		// short TTL, and the revocation paths delete the entry. Fail-open to the DB.
		Tokens:         tokens,
		AuthStateCache: store,
		AuthStateTTL:   cfg.AuthStateCacheTTL,
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
	// Keyed per user, not per IP: the consent-info peek is authenticated, and the
	// campus shares one NAT egress IP.
	consentInfoLimiter := oauthredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitConsentInfoRPM,
			Window: cfg.RateLimitConsentInfoWindow,
		},
	}
	oauthService := oauth.Service{
		Users:              users,
		Clients:            clients,
		Authorizations:     repository.NewOAuthAuthorization(database),
		Tokens:             tokens,
		Audit:              audit,
		Profiles:           users,
		Requests:           oauthredis.AuthorizeRequestStore{Store: store},
		Blacklist:          oauthredis.BlacklistStore{Store: store},
		AuthorizeLimiter:   authorizeLimiter,
		ConsentInfoLimiter: consentInfoLimiter,
		TokenLimiter:       tokenLimiter,
		JWT:                jwtManager,
		RefreshTokens:      refreshManager,
		AccessTTL:          cfg.JWTAccessTokenExpiry,
		RefreshTTL:         cfg.JWTRefreshTokenExpiry,
		CodeTTL:            cfg.OAuthCodeTTL,
		RequestTTL:         cfg.OAuthAuthorizeRequestTTL,
		// The discovery document's issuer must equal the iss claim of every issued
		// token, so both read the same setting.
		Issuer: cfg.JWTIssuer,
	}

	// Third-party login providers. Only the enabled ones are registered, and the
	// service answers 400 for a provider absent from the map, so a disabled
	// provider's route exists but declines rather than 404ing.
	loginProviders := make(map[model.LoginMethod]oauthlogin.ProviderClient)
	if cfg.OAuthGitHubEnabled {
		loginProviders[model.LoginMethodGitHub] = provider.NewGitHub(provider.GitHubConfig{
			ClientID:     cfg.OAuthGitHubClientID,
			ClientSecret: cfg.OAuthGitHubClientSecret,
			RedirectURI:  cfg.OAuthGitHubRedirectURI,
		}, nil, nil)
	}
	if cfg.OAuthLarkEnabled {
		loginProviders[model.LoginMethodLark] = provider.NewLark(provider.LarkConfig{
			AppID:       cfg.OAuthLarkClientID,
			AppSecret:   cfg.OAuthLarkClientSecret,
			RedirectURI: cfg.OAuthLarkRedirectURI,
			// Config validation requires this whenever Lark is enabled, so the
			// tenant gate cannot be silently disabled in production.
			TenantKey: cfg.OAuthLarkTenantKey,
		}, nil, nil)
	}
	oauthLoginAuthorizeLimiter := oauthloginredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitOAuthLoginRPM,
			Window: cfg.RateLimitOAuthLoginWindow,
		},
	}
	oauthLoginExchangeLimiter := oauthloginredis.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitExchangeCodeRPM,
			Window: cfg.RateLimitExchangeCodeWindow,
		},
	}
	oauthLoginService := oauthlogin.Service{
		Providers:         loginProviders,
		AuthorizeLimiter:  oauthLoginAuthorizeLimiter,
		ExchangeLimiter:   oauthLoginExchangeLimiter,
		Users:             users,
		Identities:        identities,
		Clients:           clients,
		Tokens:            tokens,
		Audits:            audit,
		States:            oauthLoginStates,
		RegistrationState: oauthRegistrations,
		LoginCodes:        oauthLoginCodes,
		// Third-party logins register as devices in the same Redis store as
		// password logins, so they count against the 5-device cap and appear in
		// the device list.
		Devices:   sessionredis.DeviceStore{Store: store},
		Blacklist: blacklist,
		Issuer: tokenissue.Issuer{
			JWT:     jwtManager,
			Refresh: refreshManager,
		},
		InternalClientID:     cfg.InternalOAuthClientID,
		AllowedRedirects:     cfg.OAuthLoginRedirects,
		StateTTL:             cfg.OAuthLoginStateTTL,
		RegistrationStateTTL: cfg.OAuthLoginRegistrationStateTTL,
		LoginCodeTTL:         cfg.OAuthLoginCodeTTL,
		AccessTTL:            cfg.JWTAccessTokenExpiry,
		RefreshTTL:           cfg.JWTRefreshTokenExpiry,
	}
	// The first allow-listed redirect is the default for a callback that names
	// none, so a login started without one still lands somewhere valid.
	if len(cfg.OAuthLoginRedirects) > 0 {
		oauthLoginService.DefaultRedirect = cfg.OAuthLoginRedirects[0]
	}

	adminUserService := adminuser.Service{
		Users:     users,
		Audit:     audit,
		Blacklist: oauthredis.BlacklistStore{Store: store},
		// Admin session-killing actions clear the user's device records in the
		// same Redis store, so a demoted/closed account leaves no ghost logins.
		Devices: sessionredis.DeviceStore{Store: store},
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
		OAuthLogin: oauthloginhandler.Handler{
			Service:       oauthLoginService,
			ErrorRedirect: cfg.OAuthLoginErrorRedirect,
		},
		Admin: adminhandler.Handler{
			Clients:   adminClientService,
			Users:     adminUserService,
			AuditLogs: adminUserService,
		},
		Auth: authenticator,
		Workers: []backgroundWorker{
			sessionworker.TokenBlacklist{Outbox: outbox, AuthState: blacklist},
			forgotPasswords,
			worker.Retention{
				Store:            repository.NewRetention(database),
				Interval:         cfg.RetentionInterval,
				BatchSize:        cfg.RetentionBatchSize,
				AuthorizationAge: cfg.RetentionAuthorizationAge,
				AccessTokenAge:   cfg.RetentionAccessTokenAge,
				RefreshTokenAge:  cfg.RetentionRefreshTokenAge,
				AuditLogAge:      cfg.RetentionAuditLogAge,
			},
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
