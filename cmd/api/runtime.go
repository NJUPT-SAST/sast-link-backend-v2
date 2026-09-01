package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	cosadapter "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/cos"
	alumniredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/alumni"
	oauthredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/oauth"
	oauthloginredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/oauthlogin"
	sessionredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/turnstile"
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
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/alumnirequest"
	alumnirequestworker "github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/alumnirequest/worker"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauthlogin"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	sessionworker "github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session/worker"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/tokenissue"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/adminhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/alumnihandler"
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
	Alumni     alumnihandler.Handler
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
	// Every endpoint limiter below shares one skeleton — client, keys,
	// limit and window — differing only in the quota. Builders keep the 16
	// near-identical literals from drifting (audit finding #11).
	newSessionLimiter := func(limit int, window time.Duration) sessionredis.EndpointLimiter {
		return sessionredis.EndpointLimiter{
			Limiter: internalredis.FixedWindowLimiter{Client: rdb, Keys: keys, Limit: limit, Window: window},
		}
	}
	newOAuthLimiter := func(limit int, window time.Duration) oauthredis.EndpointLimiter {
		return oauthredis.EndpointLimiter{
			Limiter: internalredis.FixedWindowLimiter{Client: rdb, Keys: keys, Limit: limit, Window: window},
		}
	}
	newOAuthLoginLimiter := func(limit int, window time.Duration) oauthloginredis.EndpointLimiter {
		return oauthloginredis.EndpointLimiter{
			Limiter: internalredis.FixedWindowLimiter{Client: rdb, Keys: keys, Limit: limit, Window: window},
		}
	}
	newAlumniLimiter := func(limit int, window time.Duration) alumniredis.EndpointLimiter {
		return alumniredis.EndpointLimiter{
			Limiter: internalredis.FixedWindowLimiter{Client: rdb, Keys: keys, Limit: limit, Window: window},
		}
	}
	// The tombstone TTL must outlive the longest in-flight request, so size it
	// from WriteTimeout plus a margin.
	store := internalredis.Store{
		Client:                rdb,
		Keys:                  keys,
		AuthStateTombstoneTTL: ServerWriteTimeout + 5*time.Second,
	}
	blacklist := sessionredis.BlacklistStore{Store: store}
	limiter := newSessionLimiter(cfg.RateLimitLoginRPM, cfg.RateLimitLoginWindow)
	emailLimiter := newSessionLimiter(cfg.RateLimitSendEmailRPM, cfg.RateLimitSendEmailWindow)
	emailIPLimiter := newSessionLimiter(cfg.RateLimitSendEmailIPRPM, cfg.RateLimitSendEmailWindow)
	failures := sessionredis.LoginFailureStore{Store: store, Limit: cfg.LoginFailureLimit, Window: cfg.LoginFailureWindow}
	bindTickets := sessionredis.BindTicketStore{Store: store}
	oauthLoginStates := oauthloginredis.StateStore{Store: store}
	oauthRegistrations := oauthloginredis.RegistrationStateStore{Store: store}
	oauthLoginCodes := oauthloginredis.LoginCodeStore{Store: store}
	unbindLimiter := newSessionLimiter(cfg.RateLimitUnbindRPM, cfg.RateLimitUnbindWindow)
	registerLimiter := newSessionLimiter(cfg.RateLimitRegisterAttempts, cfg.RateLimitRegisterWindow)
	refreshLimiter := newSessionLimiter(cfg.RateLimitRefreshRPM, cfg.RateLimitRefreshWindow)
	avatarLimiter := newSessionLimiter(cfg.RateLimitUploadAvatarRPM, cfg.RateLimitUploadAvatarWindow)
	deviceLimiter := newSessionLimiter(cfg.RateLimitDeviceRPM, cfg.RateLimitDeviceWindow)
	// Object storage is optional: unconfigured, PUT /user/avatar answers 50002;
	// when configured the COS client also carries fail-closed image review.
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

	// One argon2id pool shared across all KDF work: same parameters, one CPU semaphore.
	passwordHasher := auth.PasswordHasher{
		Semaphore:     make(chan struct{}, cfg.Argon2Concurrency),
		Argon2Time:    cfg.Argon2Time,
		Argon2Memory:  cfg.Argon2Memory,
		Argon2Threads: cfg.Argon2Threads,
	}

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
		// Reads the key oauthloginredis.RegistrationStateStore writes, redeemable by POST /auth/register.
		OAuthRegistration: sessionredis.OAuthRegistrationStore{Store: store},
		UnbindLimiter:     unbindLimiter,
		RegisterLimiter:   registerLimiter,
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
		Passwords:         passwordHasher,
		AccessTTL:         cfg.JWTAccessTokenExpiry,
		RefreshTTL:        cfg.JWTRefreshTokenExpiry,
	}
	authenticator := middleware.Authenticator{
		JWT: jwtManager,
		// The auth-state cache is fail-open: a miss or error falls back to the DB check.
		Tokens:         tokens,
		AuthStateCache: store,
		AuthStateTTL:   cfg.AuthStateCacheTTL,
		// Pins the internal API to the built-in client so a third-party token cannot be a session credential.
		InternalClientID: cfg.InternalOAuthClientID,
		// Delegated administration needs no wiring here: a third-party token reaches
		// /admin by carrying an admin scope.
	}

	authorizeLimiter := newOAuthLimiter(cfg.RateLimitAuthorizeRPM, cfg.RateLimitAuthorizeWindow)
	tokenLimiter := newOAuthLimiter(cfg.RateLimitTokenRPM, cfg.RateLimitTokenWindow)
	// Keyed per user, not per IP: this surface is authenticated and the campus shares one NAT egress.
	consentInfoLimiter := newOAuthLimiter(cfg.RateLimitConsentInfoRPM, cfg.RateLimitConsentInfoWindow)
	// Consent submission mints codes, so it gets its own per-user budget; userinfo
	// is deliberately unbudgeted — it requires a valid token and campus NAT is shared.
	consentLimiter := newOAuthLimiter(cfg.RateLimitConsentRPM, cfg.RateLimitConsentWindow)
	grantsLimiter := newOAuthLimiter(cfg.RateLimitGrantsRPM, cfg.RateLimitGrantsWindow)
	oauthService := oauth.Service{
		Users:                        users,
		Clients:                      clients,
		Authorizations:               repository.NewOAuthAuthorization(database),
		Tokens:                       tokens,
		Audit:                        audit,
		Profiles:                     users,
		Requests:                     oauthredis.AuthorizeRequestStore{Store: store},
		Blacklist:                    oauthredis.BlacklistStore{Store: store},
		AuthorizeLimiter:             authorizeLimiter,
		ConsentInfoLimiter:           consentInfoLimiter,
		ConsentLimiter:               consentLimiter,
		GrantsLimiter:                grantsLimiter,
		TokenLimiter:                 tokenLimiter,
		JWT:                          jwtManager,
		RefreshTokens:                refreshManager,
		AccessTTL:                    cfg.JWTAccessTokenExpiry,
		RefreshTTL:                   cfg.JWTRefreshTokenExpiry,
		CapabilityRefreshMaxLifetime: cfg.JWTRefreshCapabilityMaxLifetime,
		CodeTTL:                      cfg.OAuthCodeTTL,
		RequestTTL:                   cfg.OAuthAuthorizeRequestTTL,
		// Issuer must match the iss claim of every issued token, so both read one setting.
		Issuer: cfg.JWTIssuer,
	}

	// Third-party login providers; a disabled provider's route stays registered but declines (400).
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
			// Config validation requires this whenever Lark is enabled, so the tenant gate cannot be silently disabled.
			TenantKey: cfg.OAuthLarkTenantKey,
		}, nil, nil)
	}
	oauthLoginAuthorizeLimiter := newOAuthLoginLimiter(cfg.RateLimitOAuthLoginRPM, cfg.RateLimitOAuthLoginWindow)
	oauthLoginExchangeLimiter := newOAuthLoginLimiter(cfg.RateLimitExchangeCodeRPM, cfg.RateLimitExchangeCodeWindow)
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
		// Third-party logins register as devices in the same store as password
		// logins, so they count against the cap and appear in the list.
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
	// The first allow-listed redirect is the default for a callback that names none.
	if len(cfg.OAuthLoginRedirects) > 0 {
		oauthLoginService.DefaultRedirect = cfg.OAuthLoginRedirects[0]
	}

	adminUserService := adminuser.Service{
		Users:     users,
		Audit:     audit,
		Blacklist: oauthredis.BlacklistStore{Store: store},
		// Admin session-killing actions clear device records here, so a demoted/closed account leaves no ghosts.
		Devices: sessionredis.DeviceStore{Store: store},
		// Recorded as the audit actor when no azp is present; must match the authenticator's pinned client.
		ConsoleClientID: cfg.InternalOAuthClientID,
		Passwords:       passwordHasher,
	}

	// The captcha verifier is never nil: without a configured secret the composition
	// root injects one that refuses everything (fail-closed against unverified writes).
	var captchaVerifier alumnirequest.CaptchaVerifier = turnstile.Unavailable{}
	if strings.TrimSpace(cfg.TurnstileSecret) != "" {
		verifier, err := turnstile.New(turnstile.Config{
			Secret:         cfg.TurnstileSecret,
			ExpectedAction: cfg.TurnstileAction,
			Timeout:        cfg.TurnstileTimeout,
		})
		if err != nil {
			return nil, fmt.Errorf("construct Turnstile verifier: %w", err)
		}
		captchaVerifier = verifier
	}
	alumniRequests := repository.NewAlumniRequest(database)
	alumniNotifier := alumnirequestworker.New(alumniRequests, emailer,
		cfg.AlumniResetURL, cfg.AlumniSupportEmail)
	alumniService := alumnirequest.Service{
		Requests:        alumniRequests,
		Users:           users,
		Audit:           audit,
		Passwords:       passwordHasher,
		Captcha:         captchaVerifier,
		Limiter:         newAlumniLimiter(cfg.RateLimitAlumniRequestRPM, cfg.RateLimitAlumniRequestWindow),
		SubmitRateLimit: cfg.RateLimitAlumniRequestRPM,
		Notifier:        alumniNotifier,
		ConsoleClientID: cfg.InternalOAuthClientID,
	}

	adminClientService := adminclient.Service{
		Clients:   clients,
		Blacklist: oauthredis.BlacklistStore{Store: store},
		Audit:     audit,
		// Default random source and hashing; see auth.ClientSecretHasher.
		Secrets: auth.ClientSecretHasher{},
		// The same client the internal API pins its azp gate to; disabling it locks everyone out of login.
		ProtectedClientID: cfg.InternalOAuthClientID,
	}

	// oauthStateCookieName is the login-CSRF cookie written at authorize time and
	// read back at callback; it must differ from the session cookie.
	const oauthStateCookieName = "sl_oauth_state"

	// The httpOnly session cookie a fresh tab uses to rebuild a session; its value
	// is the rotating refresh token and SameSite=Lax blocks cross-site POSTs.
	sessionCookie := &middleware.SessionCookie{
		Name:     cfg.SessionCookieName,
		Path:     cfg.SessionCookiePath,
		Secure:   cfg.SessionCookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
	// The login-CSRF cookie pairs a callback with the browser that started the
	// authorization (OAuth 2.0 §10.12); its value is hex(SHA-256(state)) and it
	// shares the session cookie's path/secure posture.
	stateCookie := &middleware.SessionCookie{
		Name:     oauthStateCookieName,
		Path:     cfg.SessionCookiePath,
		Secure:   cfg.SessionCookieSecure,
		SameSite: http.SameSiteLaxMode,
	}

	// Carries the user.state recompute position across retention ticks so a table
	// larger than one tick's batch budget advances instead of restarting. Only the
	// advisory-lock holder writes it, from the worker's single goroutine.
	var derivedStateCursor int64
	return &sessionRuntime{
		Handler: sessionhandler.Handler{Service: service, Cookies: sessionCookie},
		OAuth: oauthhandler.Handler{
			Service:    oauthService,
			Auth:       authenticator,
			ConsentURL: cfg.OAuthConsentURL,
		},
		OAuthLogin: oauthloginhandler.Handler{
			Service:       oauthLoginService,
			ErrorRedirect: cfg.OAuthLoginErrorRedirect,
			Cookies:       sessionCookie,
			StateCookie:   stateCookie,
		},
		Admin: adminhandler.Handler{
			Clients:   adminClientService,
			Users:     adminUserService,
			AuditLogs: adminUserService,
		},
		Alumni: alumnihandler.Handler{Requests: alumniService},
		Auth:   authenticator,
		Workers: []backgroundWorker{
			sessionworker.TokenBlacklist{Outbox: outbox, AuthState: blacklist},
			forgotPasswords,
			alumniNotifier,
			worker.Retention{
				Store:              repository.NewRetention(database),
				Interval:           cfg.RetentionInterval,
				BatchSize:          cfg.RetentionBatchSize,
				AuthorizationAge:   cfg.RetentionAuthorizationAge,
				AccessTokenAge:     cfg.RetentionAccessTokenAge,
				RefreshTokenAge:    cfg.RetentionRefreshTokenAge,
				AuditLogAge:        cfg.RetentionAuditLogAge,
				AlumniRequestAge:   cfg.RetentionAlumniRequestAge,
				DerivedStateCursor: &derivedStateCursor,
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
