// Command api runs the SAST Link v2 HTTP API server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	goredis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/db"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/health"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/sessionadapter"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/sessionhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/worker"
)

const serverShutdownTimeout = 10 * time.Second

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if os.Getenv("APP_ENV") != "production" {
		_ = godotenv.Load()
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if validateErr := cfg.ValidateAPIAuth(); validateErr != nil {
		return fmt.Errorf("validate API auth config: %w", validateErr)
	}

	setupLogger(cfg.LogLevel)

	database, err := db.Open(cfg.PostgresDSN())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close(database) }()

	rdb, err := internalredis.New(cfg.RedisAddr(), cfg.RedisPassword, cfg.RedisDB)
	if err != nil {
		return fmt.Errorf("open redis: %w", err)
	}
	defer func() { _ = internalredis.Close(rdb) }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runtime, err := buildSessionRuntime(ctx, cfg, database, rdb)
	if err != nil {
		return err
	}

	router, err := web.NewRouter(cfg.CORSAllowedOrigins, cfg.TrustedProxies, cfg.HSTSMaxAge)
	if err != nil {
		return fmt.Errorf("create router: %w", err)
	}
	health.New(map[string]func() error{
		"db":    func() error { return pingDB(database) },
		"redis": func() error { return pingRedis(rdb) },
	}).Register(router)
	sessionhandler.RegisterRoutes(router, runtime.Handler, runtime.Auth.RequireAuth())

	slog.Info("server starting", slog.String("port", cfg.AppPort))
	return serve(ctx, ":"+cfg.AppPort, router, runtime.Workers)
}

type backgroundWorker interface {
	Run(ctx context.Context) error
}

type httpServer interface {
	ListenAndServe() error
	Shutdown(ctx context.Context) error
}

var newHTTPServer = func(address string, handler http.Handler) httpServer {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

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
	blacklist := sessionadapter.BlacklistStore{Store: store}
	limiter := sessionadapter.EndpointLimiter{
		Limiter: internalredis.FixedWindowLimiter{
			Client: rdb,
			Keys:   keys,
			Limit:  cfg.RateLimitLoginRPM,
			Window: cfg.RateLimitLoginWindow,
		},
	}
	failures := sessionadapter.LoginFailureStore{Store: store, Limit: cfg.LoginFailureLimit, Window: cfg.LoginFailureWindow}

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
		Workers: []backgroundWorker{worker.TokenBlacklist{Outbox: outbox, Blacklist: blacklist}},
	}, nil
}

func serve(ctx context.Context, address string, handler http.Handler, workers []backgroundWorker) error {
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	workerErrors := make(chan error, len(workers))
	var workerGroup sync.WaitGroup
	workerGroup.Add(len(workers))
	for _, background := range workers {
		background := background
		go func() {
			defer workerGroup.Done()
			if err := background.Run(workerCtx); err != nil {
				workerErrors <- err
			}
		}()
	}
	go func() {
		workerGroup.Wait()
		close(workerErrors)
	}()

	server := newHTTPServer(address, handler)
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("serve HTTP: %w", err)
		}
	case err, ok := <-workerErrors:
		if ok {
			runErr = fmt.Errorf("run background worker: %w", err)
		} else if ctx.Err() == nil {
			runErr = fmt.Errorf("background workers stopped unexpectedly")
		}
	}

	cancelWorkers()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), serverShutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil && runErr == nil {
		runErr = fmt.Errorf("shutdown HTTP server: %w", err)
	}
	for {
		select {
		case err, ok := <-workerErrors:
			if !ok {
				return runErr
			}
			if runErr == nil {
				runErr = fmt.Errorf("stop background worker: %w", err)
			}
		case <-shutdownCtx.Done():
			if runErr == nil {
				runErr = fmt.Errorf("stop background workers: %w", shutdownCtx.Err())
			}
			return runErr
		}
	}
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

func setupLogger(level string) {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{Level: slogLevel},
	)))
}

func pingDB(database *gorm.DB) error {
	sqlDB, err := database.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

func pingRedis(client *goredis.Client) error {
	return client.Ping(context.Background()).Err()
}
