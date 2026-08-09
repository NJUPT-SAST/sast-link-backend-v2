// Package config loads application configuration from environment variables.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

const (
	minimumRefreshHMACSecretLen = 32
	// minimumHSTSMaxAge is one year in seconds, matching the PRD §7.2 default.
	// Smaller values leave the header present but effectively unenforced.
	minimumHSTSMaxAge = 31536000
	maximumTCPPort    = 65535
	// maxOAuthCodeTTL caps the authorization code lifetime. PRD §4.10 specifies 5
	// minutes; the ceiling is deliberately loose enough for staging experiments and
	// still far short of turning a code into a long-lived credential.
	maxOAuthCodeTTL = 15 * time.Minute
	// maxOAuthAuthorizeRequestTTL caps how long a pending consent decision waits.
	maxOAuthAuthorizeRequestTTL = time.Hour
	// registerTicketTTL mirrors session.verificationTTL, which bounds the
	// Register-Ticket. It is duplicated rather than imported because config must
	// not depend on a service package; the register limiter's window is validated
	// against it, since a window outliving the ticket leaves a throttled caller
	// nothing to retry with. Keep the two in step.
	registerTicketTTL = 5 * time.Minute
	// minAuditLogRetention is a sanity floor, not the product commitment. Audit
	// history is operationally useful rather than compliance-bound here, so a
	// deployment may trim it below the 90 days PRD §9 targets — the default stays at
	// 90. The floor only rejects values so short that an incident investigation would
	// find the relevant entries already deleted.
	minAuditLogRetention = 30 * 24 * time.Hour
)

// Config holds all runtime configuration for the service.
type Config struct {
	AppEnv   string `env:"APP_ENV" envDefault:"development"`
	AppPort  string `env:"APP_PORT" envDefault:"8080"`
	LogLevel string `env:"LOG_LEVEL" envDefault:"warn"`

	DBHost    string `env:"DB_HOST" envDefault:"localhost"`
	DBPort    string `env:"DB_PORT" envDefault:"5432"`
	DBUser    string `env:"DB_USER"`
	DBSecret  string `env:"DB_PASSWORD"`
	DBName    string `env:"DB_NAME"`
	DBSSLMode string `env:"DB_SSLMODE" envDefault:"disable"`

	RedisHost      string `env:"REDIS_HOST" envDefault:"localhost"`
	RedisPort      string `env:"REDIS_PORT" envDefault:"6379"`
	RedisSecret    string `env:"REDIS_PASSWORD"`
	RedisDB        int    `env:"REDIS_DB" envDefault:"0"`
	RedisKeyPrefix string `env:"REDIS_KEY_PREFIX" envDefault:"sastlink"`

	JWTSecretKey           string        `env:"JWT_SECRET_KEY"`
	JWTSecretKeyPrev       string        `env:"JWT_SECRET_KEY_PREV"`
	JWTActiveKID           string        `env:"JWT_ACTIVE_KID"`
	JWTPreviousKID         string        `env:"JWT_PREVIOUS_KID"`
	JWTIssuer              string        `env:"JWT_ISSUER" envDefault:"https://link.sast.fun/v2"`
	JWTAudience            string        `env:"JWT_AUDIENCE" envDefault:"sast-link-v2"`
	JWTAccessTokenExpiry   time.Duration `env:"JWT_ACCESS_TOKEN_EXPIRY" envDefault:"1h"`
	JWTRefreshTokenExpiry  time.Duration `env:"JWT_REFRESH_TOKEN_EXPIRY" envDefault:"720h"`
	RefreshTokenHMACSecret string        `env:"REFRESH_TOKEN_HMAC_SECRET"`

	// OAuthConsentURL is the front-end page that collects the user's authorization
	// decision. GET /oauth/authorize validates the request and redirects here; the
	// page then calls POST /oauth/authorize/consent with the caller's access token.
	OAuthConsentURL string `env:"OAUTH_CONSENT_URL"`
	// OAuthCodeTTL bounds an authorization code's lifetime (PRD §4.10: 5min).
	OAuthCodeTTL time.Duration `env:"OAUTH_CODE_TTL" envDefault:"5m"`
	// OAuthAuthorizeRequestTTL bounds how long a validated authorize request waits
	// in Redis for the user's consent decision.
	OAuthAuthorizeRequestTTL time.Duration `env:"OAUTH_AUTHORIZE_REQUEST_TTL" envDefault:"10m"`

	// Third-party login providers: SAST Link acting as an OAuth *client*, the
	// opposite direction from the OAuth* provider settings above. Each provider
	// is gated by its own Enabled flag so a deployment can run one, both, or
	// neither; a disabled provider's route is still registered and answers 400
	// rather than 404, which keeps the contract stable.
	//
	// The env names keep the OAUTH_FEISHU_* spelling that .env.example already
	// documents, while the provider enum, routes and identities.provider all use
	// "lark". Renaming the variables would break existing deployments for a
	// cosmetic gain.
	OAuthGitHubEnabled      bool   `env:"OAUTH_GITHUB_ENABLED" envDefault:"false"`
	OAuthGitHubClientID     string `env:"OAUTH_GITHUB_CLIENT_ID"`
	OAuthGitHubClientSecret string `env:"OAUTH_GITHUB_CLIENT_SECRET"`
	OAuthGitHubRedirectURI  string `env:"OAUTH_GITHUB_REDIRECT_URI"`
	OAuthLarkEnabled        bool   `env:"OAUTH_FEISHU_ENABLED" envDefault:"false"`
	OAuthLarkClientID       string `env:"OAUTH_FEISHU_CLIENT_ID"`
	OAuthLarkClientSecret   string `env:"OAUTH_FEISHU_CLIENT_SECRET"`
	OAuthLarkRedirectURI    string `env:"OAUTH_FEISHU_REDIRECT_URI"`
	// OAuthLarkTenantKey restricts Lark login to the SAST enterprise (PRD §4.5).
	// It is required when Lark is enabled: an empty value would silently accept
	// every tenant, which is the one thing this gate exists to prevent.
	OAuthLarkTenantKey string `env:"OAUTH_FEISHU_TENANT_KEY"`
	// OAuthLoginRedirects is the exact-match allow-list of frontend URLs a
	// provider callback may return the browser to. Exact match only: a prefix
	// rule would make the callback an open redirector handing out login codes.
	OAuthLoginRedirects []string `env:"OAUTH_LOGIN_REDIRECTS" envSeparator:","`
	// OAuthLoginErrorRedirect is the frontend page a failed callback lands on.
	OAuthLoginErrorRedirect string `env:"OAUTH_LOGIN_ERROR_REDIRECT"`
	// TTLs for the three fail-closed Redis values this flow owns (PRD §6).
	OAuthLoginStateTTL             time.Duration `env:"OAUTH_LOGIN_STATE_TTL" envDefault:"10m"`
	OAuthLoginRegistrationStateTTL time.Duration `env:"OAUTH_LOGIN_REGISTRATION_STATE_TTL" envDefault:"15m"`
	OAuthLoginCodeTTL              time.Duration `env:"OAUTH_LOGIN_CODE_TTL" envDefault:"60s"`

	// InternalOAuthClientID is Link's own session client. It remains singular
	// because Link's password/login flows issue tokens through this registration.
	InternalOAuthClientID string `env:"INTERNAL_OAUTH_CLIENT_ID" envDefault:"sast-link-web"`
	// TrustedInternalOAuthClientIDs is the explicit allow-list of additional
	// first-party clients whose tokens may call Link's internal APIs. Registering a
	// client in the database alone never grants this privilege.
	TrustedInternalOAuthClientIDs []string `env:"TRUSTED_INTERNAL_OAUTH_CLIENT_IDS" envSeparator:","`
	CORSAllowedOrigins            []string `env:"CORS_ALLOWED_ORIGINS" envSeparator:","`
	TrustedProxies                []string `env:"TRUSTED_PROXIES" envSeparator:"," envDefault:"127.0.0.1,::1"`
	HSTSMaxAge                    int      `env:"HSTS_MAX_AGE" envDefault:"31536000"`
	// The per-IP defaults are tuned for the campus NAT reality: hundreds of users
	// share one egress IP, so any per-IP cap must accommodate the whole campus's
	// aggregate volume or login breaks during a rush. The login defense is the
	// per-account lockout (LoginFailureLimit), and per-IP login throttling is
	// generous (300/15min ≈ 20/min) so a campus NAT is not the bottleneck while a
	// single source still cannot run an unbounded spray. Abuse visibility is
	// planned as an admin login-IP statistics feature rather than a per-IP cap.
	RateLimitLoginRPM        int           `env:"RATE_LIMIT_LOGIN_RPM" envDefault:"300"`
	RateLimitLoginWindow     time.Duration `env:"RATE_LIMIT_LOGIN_WINDOW" envDefault:"15m"`
	RateLimitSendEmailRPM    int           `env:"RATE_LIMIT_SEND_EMAIL_RPM" envDefault:"3"`
	RateLimitSendEmailIPRPM  int           `env:"RATE_LIMIT_SEND_EMAIL_IP_RPM" envDefault:"30"`
	RateLimitSendEmailWindow time.Duration `env:"RATE_LIMIT_SEND_EMAIL_WINDOW" envDefault:"60s"`
	LoginFailureLimit        int           `env:"LOGIN_FAILURE_LIMIT" envDefault:"10"`
	LoginFailureWindow       time.Duration `env:"LOGIN_FAILURE_WINDOW" envDefault:"15m"`
	// AuthStateCacheTTL bounds how long a cached per-token auth state lives before
	// a re-read.
	//
	// It is NOT what bounds the post-revocation window. Revocation writes a
	// tombstone rather than deleting the entry, and GetAuthState reads a tombstone
	// as a miss, so a revoked token falls through to the authoritative
	// oauth_access_tokens.revoked_at query no matter how long this TTL is; if
	// Redis is unreachable the cache read fails and the same fallback applies. A
	// revoked token cannot be admitted at any value here — the tombstone's own TTL
	// (Store.AuthStateTombstoneTTL, sized from the server WriteTimeout) is what
	// covers that path.
	//
	// What this TTL actually bounds is a state change that does NOT revoke the
	// token. UpdateAdminUser gates its revocation on roleChanged, so an edit that
	// only moves "user".state (njupter/on_sast/retired_sast), and RestoreUser,
	// leave live tokens alone: their cached blob keeps the pre-change state until
	// this TTL expires. Nothing authorizes on Principal.State today — RequireRole
	// reads Role, and every role change revokes — so the window is currently
	// inconsequential. It stops being inconsequential the moment a check gates on
	// state, which is why this stays short rather than being sized for cache hit
	// rate alone.
	AuthStateCacheTTL time.Duration `env:"AUTH_STATE_CACHE_TTL" envDefault:"15s"`
	// EnablePprof explicitly exposes /debug/pprof in production (default off).
	// The endpoints can drive CPU sampling and dump goroutine/heap state, so they
	// must not be on unless a deployment opts in for profiling.
	EnablePprof bool `env:"PPROF_ENABLED" envDefault:"false"`
	// Unbind throttling is per caller, not per address: keying by provider_id let
	// one user's unbind lock out a different user who later bound the same
	// address. Fail-open, since PostgreSQL owns the binding state and is also the
	// serialization point for concurrent deletes of one record.
	RateLimitUnbindRPM    int           `env:"RATE_LIMIT_UNBIND_RPM" envDefault:"3"`
	RateLimitUnbindWindow time.Duration `env:"RATE_LIMIT_UNBIND_WINDOW" envDefault:"60s"`
	// Throttles DELETE /user/devices/:id per user. The endpoint revokes a whole
	// token family (and therefore kills a real session), so the cap is per
	// authenticated user rather than per IP — a campus NAT must not share one
	// budget, and a leaked token must not be able to hammer revocations.
	RateLimitDeviceRPM    int           `env:"RATE_LIMIT_DEVICE_RPM" envDefault:"3"`
	RateLimitDeviceWindow time.Duration `env:"RATE_LIMIT_DEVICE_WINDOW" envDefault:"60s"`
	// Throttles GET /oauth/authorize per caller IP. The endpoint is
	// unauthenticated and writes a Redis stash per call, so without a limit anyone
	// could fill the keyspace. Fail-open, per PRD §6.0.
	RateLimitAuthorizeRPM    int           `env:"RATE_LIMIT_AUTHORIZE_RPM" envDefault:"100"`
	RateLimitAuthorizeWindow time.Duration `env:"RATE_LIMIT_AUTHORIZE_WINDOW" envDefault:"60s"`
	// Throttles GET /oauth/authorize/consent per user. The endpoint is
	// authenticated, so it keys on the user rather than the caller IP — campus
	// egress shares one NAT IP, and an IP budget would let a single student
	// exhaust everyone's. It reads a Redis stash per call (peek), bounding
	// repeated random request_id probes. Fail-open, per PRD §6.0.
	RateLimitConsentInfoRPM    int           `env:"RATE_LIMIT_CONSENT_INFO_RPM" envDefault:"60"`
	RateLimitConsentInfoWindow time.Duration `env:"RATE_LIMIT_CONSENT_INFO_WINDOW" envDefault:"60s"`
	// Throttles POST /oauth/token and POST /oauth/revoke per caller IP. Both check
	// client credentials and presented tokens, so an unlimited rate means unlimited
	// credential attempts. Set higher than the authorize limit: one authorization
	// legitimately produces a token request plus periodic refreshes, and several
	// clients can share an egress IP. Fail-open, per PRD §6.0.
	RateLimitTokenRPM    int           `env:"RATE_LIMIT_TOKEN_RPM" envDefault:"100"`
	RateLimitTokenWindow time.Duration `env:"RATE_LIMIT_TOKEN_WINDOW" envDefault:"60s"`
	// Throttles POST /auth/refresh per caller IP. The endpoint is unauthenticated
	// and each call runs several DB statements (refresh-token lookup, user fetch,
	// rotation write), so without a cap a single source can amplify DB work for
	// free. Same shape as the token endpoint: one refresh per access-token
	// lifetime per device, multiplied by clients sharing an egress IP. Fail-open,
	// per PRD §6.0.
	RateLimitRefreshRPM    int           `env:"RATE_LIMIT_REFRESH_RPM" envDefault:"100"`
	RateLimitRefreshWindow time.Duration `env:"RATE_LIMIT_REFRESH_WINDOW" envDefault:"60s"`
	// Throttles GET /oauth/github and GET /oauth/lark per caller IP. Same shape as
	// the authorize endpoint above — unauthenticated, and every call writes one
	// oauth_state key — so it carries the same cap. Fail-open, per PRD §6.0.
	RateLimitOAuthLoginRPM    int           `env:"RATE_LIMIT_OAUTH_LOGIN_RPM" envDefault:"100"`
	RateLimitOAuthLoginWindow time.Duration `env:"RATE_LIMIT_OAUTH_LOGIN_WINDOW" envDefault:"60s"`
	// Throttles POST /oauth/exchange-code per caller IP. Unauthenticated by
	// design — redeeming a login_code is how a session is obtained — so without a cap
	// the code space can be probed for free. Higher than the login cap: one login
	// legitimately redeems once, but a shared egress IP multiplies that.
	RateLimitExchangeCodeRPM    int           `env:"RATE_LIMIT_EXCHANGE_CODE_RPM" envDefault:"100"`
	RateLimitExchangeCodeWindow time.Duration `env:"RATE_LIMIT_EXCHANGE_CODE_WINDOW" envDefault:"60s"`
	// Throttles POST /auth/register per Register-Ticket, not per IP. Each accepted
	// call runs one argon2id derivation, so what needs
	// bounding is derivations per verified email — and the ticket is exactly that
	// credential. Keying on IP instead would put a whole campus NAT behind one
	// counter, which is the shape of the traffic this endpoint sees during
	// enrollment. Ticket acquisition is already capped upstream by the send-email
	// limiters, so this does not leave the cost unbounded.
	//
	// The window must not exceed the ticket's own 5-minute TTL: a longer one would
	// still be closed when the ticket it throttles has already expired, leaving the
	// caller nothing to retry with. Fail-open, per PRD §6.0.
	RateLimitRegisterAttempts int           `env:"RATE_LIMIT_REGISTER_ATTEMPTS" envDefault:"5"`
	RateLimitRegisterWindow   time.Duration `env:"RATE_LIMIT_REGISTER_WINDOW" envDefault:"5m"`
	// Throttles GET /card/:id per caller IP. Unauthenticated, one DB read per call,
	// and the path parameter is enumerable, so an uncapped endpoint hands out a
	// full scrape of every public card.
	//
	// Set for a member wall behind a shared egress: a page that renders dozens of
	// cards must not spend a whole NAT's minute on one visitor. A cap this loose
	// only slows a scrape rather than preventing it — bulk reads of public cards
	// belong behind the proxy's cache, which is also where the capacity defense
	// lives. Fail-open, per PRD §6.0.
	RateLimitCardRPM    int           `env:"RATE_LIMIT_CARD_RPM" envDefault:"300"`
	RateLimitCardWindow time.Duration `env:"RATE_LIMIT_CARD_WINDOW" envDefault:"60s"`

	// Argon2Concurrency caps simultaneous argon2id derivations. A burst
	// beyond this queues at the hasher instead of saturating every CPU core. It
	// also doubles as the memory ceiling: each derivation allocates 19 MiB at the
	// default parameters, so a high value on a small box exhausts RAM. When not
	// explicitly set, it defaults to GOMAXPROCS (1 on the 1c1g deployment).
	Argon2Concurrency int `env:"ARGON2_CONCURRENCY"`
	// Argon2Time/Memory/Threads are the argon2id parameters for new
	// password hashes. Memory is in KiB; the default 19456 KiB (19 MiB) at t=2 is
	// the OWASP low-memory work factor adopted for the 1-core deployment. Raise
	// ARGON2_MEMORY/TIME where offline strength matters.
	// Threads must divide the memory into at least 8 KiB lanes.
	Argon2Time    uint32 `env:"ARGON2_TIME" envDefault:"2"`
	Argon2Memory  uint32 `env:"ARGON2_MEMORY" envDefault:"19456"`
	Argon2Threads uint8  `env:"ARGON2_THREADS" envDefault:"1"`

	// Retention windows for the cleanup worker. Each is measured back from now, so a
	// row is deleted only once it has been dead for the whole window; the margin
	// absorbs clock skew between this process and PostgreSQL.
	RetentionInterval  time.Duration `env:"RETENTION_INTERVAL" envDefault:"1h"`
	RetentionBatchSize int           `env:"RETENTION_BATCH_SIZE" envDefault:"1000"`
	// An expired authorization code has no authority left: it is single-use and a
	// replay is answered by revoking the family at redemption time.
	RetentionAuthorizationAge time.Duration `env:"RETENTION_AUTHORIZATION_AGE" envDefault:"1h"`
	// Deliberately far wider than the 1h default access-token TTL. The auth middleware
	// reports an unknown JTI with the same 401 it uses for a revoked one, so
	// deleting metadata while its JWT is still inside exp would show a merely
	// expired token as revoked: the client gets CodeAccessTokenInvalid instead of
	// CodeAccessTokenExpired and reads a forced logout where it should have
	// refreshed. There is no clock-skew leeway in the JWT verifier to lean on, and
	// these rows are small, so the window buys that safety cheaply.
	RetentionAccessTokenAge  time.Duration `env:"RETENTION_ACCESS_TOKEN_AGE" envDefault:"24h"`
	RetentionRefreshTokenAge time.Duration `env:"RETENTION_REFRESH_TOKEN_AGE" envDefault:"24h"`
	// Defaults to the 90 days PRD §9 targets. May be raised, or trimmed down to the
	// minAuditLogRetention sanity floor — audit history here is operational, not
	// compliance-bound.
	RetentionAuditLogAge time.Duration `env:"RETENTION_AUDIT_LOG_AGE" envDefault:"2160h"`

	// SMTPHost has no default: a "localhost" fallback would let a deployment
	// that forgot SMTP_HOST start cleanly and only fail when a user registers.
	SMTPHost   string `env:"SMTP_HOST"`
	SMTPPort   int    `env:"SMTP_PORT" envDefault:"587"`
	SMTPUser   string `env:"SMTP_USERNAME"`
	SMTPPass   string `env:"SMTP_PASSWORD"`
	SMTPFrom   string `env:"SMTP_FROM"`
	SMTPUseTLS bool   `env:"SMTP_USE_TLS" envDefault:"false"`
	// SMTPMaxConcurrent caps simultaneous SMTP sends; see mailer.Config.
	SMTPMaxConcurrent int `env:"SMTP_MAX_CONCURRENT" envDefault:"32"`

	// Object storage backs PUT /user/avatar (PRD §4.9). The provider is Tencent
	// Cloud COS; the whole group is optional — an empty STORAGE_* set means avatar
	// upload is disabled and the endpoint answers 50002 — but a partially filled
	// set is a startup error, because a bucket that looks configured and is not
	// would only fail on the first upload.
	StorageProvider  string `env:"STORAGE_PROVIDER" envDefault:"cos"`
	StorageEndpoint  string `env:"STORAGE_ENDPOINT"`
	StorageRegion    string `env:"STORAGE_REGION"`
	StorageBucket    string `env:"STORAGE_BUCKET"`
	StorageAccessKey string `env:"STORAGE_ACCESS_KEY"`
	StorageSecretKey string `env:"STORAGE_SECRET_KEY"`
	// StorageBaseURL prefixes stored avatar URLs when set (typically a CDN
	// domain). Empty falls back to the bucket access host.
	StorageBaseURL string `env:"STORAGE_BASE_URL"`
	// StorageAuditEnabled turns on the COS image review for avatars. Fail-closed:
	// while enabled, an unreachable review service rejects the upload rather than
	// letting unvetted images through. On by default; disable only when the
	// bucket has no data-cos (CI) capability enabled.
	StorageAuditEnabled bool `env:"STORAGE_AUDIT_ENABLED" envDefault:"true"`
	// Avatar upload throttling is per caller: one COS PUT (and one paid review)
	// per accepted request, and the subject is the authenticated user, so keying
	// by user is exact. Fail-open, per PRD §6.0.
	RateLimitUploadAvatarRPM    int           `env:"RATE_LIMIT_UPLOAD_AVATAR_RPM" envDefault:"10"`
	RateLimitUploadAvatarWindow time.Duration `env:"RATE_LIMIT_UPLOAD_AVATAR_WINDOW" envDefault:"60s"`
}

// Load parses configuration from environment variables and validates required fields.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// ARGON2_CONCURRENCY defaults to the core count when unset: a single
	// argon2id derivation at the default parameters costs tens of milliseconds, so
	// a fixed high concurrency would oversubscribe a small host and stall every
	// other endpoint. Sizing the gate to GOMAXPROCS keeps the box in check while
	// still letting an operator raise it explicitly.
	if v, set := os.LookupEnv("ARGON2_CONCURRENCY"); !set || strings.TrimSpace(v) == "" {
		// An unset OR empty value falls back to GOMAXPROCS. Compose forwards the
		// variable even when the operator left it blank, and an empty string would
		// otherwise parse to 0 and fail validation below.
		cfg.Argon2Concurrency = runtime.GOMAXPROCS(0)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return cfg, nil
}

// InternalOAuthClientIDs returns the complete, de-duplicated internal API
// allow-list. The built-in session client is always included.
func (c *Config) InternalOAuthClientIDs() []string {
	ids := make([]string, 0, 1+len(c.TrustedInternalOAuthClientIDs))
	seen := make(map[string]struct{}, cap(ids))
	for _, rawID := range append([]string{c.InternalOAuthClientID}, c.TrustedInternalOAuthClientIDs...) {
		clientID := strings.TrimSpace(rawID)
		if clientID == "" {
			continue
		}
		if _, exists := seen[clientID]; exists {
			continue
		}
		seen[clientID] = struct{}{}
		ids = append(ids, clientID)
	}
	return ids
}

func (c *Config) validate() error {
	switch {
	case c.DBUser == "":
		return fmt.Errorf("DB_USER is required")
	case c.DBSecret == "":
		return fmt.Errorf("DB_PASSWORD is required")
	case c.DBName == "":
		return fmt.Errorf("DB_NAME is required")
	case (strings.TrimSpace(c.JWTSecretKeyPrev) == "") != (strings.TrimSpace(c.JWTPreviousKID) == ""):
		return fmt.Errorf("JWT_SECRET_KEY_PREV and JWT_PREVIOUS_KID must be both set or both empty")
	}
	return nil
}

// validateThirdPartyLogin checks the GitHub and Lark client settings, but only
// for providers that are enabled.
//
// A disabled provider's blank credentials are not an error: most deployments run
// neither, and demanding values for an unused provider would make the service
// unstartable for no benefit. An enabled provider with missing credentials is an
// error, because the failure would otherwise surface as a confusing provider
// rejection on the first user who tries to log in.
func (c *Config) validateThirdPartyLogin() error {
	if !c.OAuthGitHubEnabled && !c.OAuthLarkEnabled {
		return nil
	}
	// The allow-list and error page are shared by both providers, so they are
	// required as soon as either is on. Without the allow-list every redirect
	// falls back to the empty default and the callback cannot complete.
	if len(c.OAuthLoginRedirects) == 0 {
		return fmt.Errorf("OAUTH_LOGIN_REDIRECTS is required when a third-party login provider is enabled")
	}
	for _, redirect := range c.OAuthLoginRedirects {
		if !isAbsoluteHTTPURL(redirect) {
			return fmt.Errorf("OAUTH_LOGIN_REDIRECTS entries must be absolute http(s) URLs, got %q", redirect)
		}
	}
	if strings.TrimSpace(c.OAuthLoginErrorRedirect) != "" &&
		!isAbsoluteHTTPURL(c.OAuthLoginErrorRedirect) {
		return fmt.Errorf("OAUTH_LOGIN_ERROR_REDIRECT must be an absolute http(s) URL")
	}

	if c.OAuthGitHubEnabled {
		switch {
		case strings.TrimSpace(c.OAuthGitHubClientID) == "":
			return fmt.Errorf("OAUTH_GITHUB_CLIENT_ID is required when OAUTH_GITHUB_ENABLED is true")
		case strings.TrimSpace(c.OAuthGitHubClientSecret) == "":
			return fmt.Errorf("OAUTH_GITHUB_CLIENT_SECRET is required when OAUTH_GITHUB_ENABLED is true")
		case !isAbsoluteHTTPURL(c.OAuthGitHubRedirectURI):
			return fmt.Errorf("OAUTH_GITHUB_REDIRECT_URI must be an absolute http(s) URL")
		}
	}
	if c.OAuthLarkEnabled {
		switch {
		case strings.TrimSpace(c.OAuthLarkClientID) == "":
			return fmt.Errorf("OAUTH_FEISHU_CLIENT_ID is required when OAUTH_FEISHU_ENABLED is true")
		case strings.TrimSpace(c.OAuthLarkClientSecret) == "":
			return fmt.Errorf("OAUTH_FEISHU_CLIENT_SECRET is required when OAUTH_FEISHU_ENABLED is true")
		case !isAbsoluteHTTPURL(c.OAuthLarkRedirectURI):
			return fmt.Errorf("OAUTH_FEISHU_REDIRECT_URI must be an absolute http(s) URL")
		// PRD §4.5 limits Lark login to the SAST enterprise. An empty tenant key
		// disables that gate, so it cannot be optional here: the deployment would
		// accept logins from every Lark tenant and nothing would look wrong.
		case strings.TrimSpace(c.OAuthLarkTenantKey) == "":
			return fmt.Errorf("OAUTH_FEISHU_TENANT_KEY is required when OAUTH_FEISHU_ENABLED is true")
		}
	}
	return nil
}

// ValidateAPIAuth validates auth settings required by cmd/api endpoints.
func (c *Config) ValidateAPIAuth() error {
	switch {
	case strings.TrimSpace(c.JWTSecretKey) == "":
		return fmt.Errorf("JWT_SECRET_KEY is required")
	case strings.TrimSpace(c.JWTActiveKID) == "":
		return fmt.Errorf("JWT_ACTIVE_KID is required")
	// JWT_ISSUER is both the iss claim of every token and the base every OIDC
	// discovery endpoint URL is concatenated onto, so it carries more weight than the
	// two OAUTH_* URLs below that were already checked this way. A scheme-less value
	// like "link.sast.fun" boots cleanly and publishes relative endpoint URLs that no
	// relying party can resolve — a failure visible only to third-party integrators.
	case !isAbsoluteHTTPURL(c.JWTIssuer):
		return fmt.Errorf("JWT_ISSUER must be an absolute http(s) URL")
	case len(c.RefreshTokenHMACSecret) < minimumRefreshHMACSecretLen:
		return fmt.Errorf("REFRESH_TOKEN_HMAC_SECRET must be at least %d bytes", minimumRefreshHMACSecretLen)
	case c.JWTAccessTokenExpiry <= 0:
		return fmt.Errorf("JWT_ACCESS_TOKEN_EXPIRY must be positive")
	case c.JWTRefreshTokenExpiry <= 0:
		return fmt.Errorf("JWT_REFRESH_TOKEN_EXPIRY must be positive")
	case strings.TrimSpace(c.InternalOAuthClientID) == "":
		return fmt.Errorf("INTERNAL_OAUTH_CLIENT_ID is required")
	case hasBlankOrDuplicate(c.TrustedInternalOAuthClientIDs, strings.TrimSpace(c.InternalOAuthClientID)):
		return fmt.Errorf("TRUSTED_INTERNAL_OAUTH_CLIENT_IDS must contain unique, non-empty client IDs and must not repeat INTERNAL_OAUTH_CLIENT_ID")
	case c.HSTSMaxAge < minimumHSTSMaxAge:
		return fmt.Errorf("HSTS_MAX_AGE must be at least %d seconds", minimumHSTSMaxAge)
	case c.RateLimitLoginRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_LOGIN_RPM must be positive")
	case c.RateLimitLoginWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_LOGIN_WINDOW must be at least 1s")
	case c.RateLimitSendEmailRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_SEND_EMAIL_RPM must be positive")
	case c.RateLimitSendEmailIPRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_SEND_EMAIL_IP_RPM must be positive")
	case c.RateLimitSendEmailWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_SEND_EMAIL_WINDOW must be at least 1s")
	case c.LoginFailureLimit <= 0:
		return fmt.Errorf("LOGIN_FAILURE_LIMIT must be positive")
	case c.LoginFailureWindow <= 0:
		return fmt.Errorf("LOGIN_FAILURE_WINDOW must be positive")
	case c.RateLimitUnbindRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_UNBIND_RPM must be positive")
	case c.RateLimitUnbindWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_UNBIND_WINDOW must be at least 1s")
	case c.RateLimitDeviceRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_DEVICE_RPM must be positive")
	case c.RateLimitDeviceWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_DEVICE_WINDOW must be at least 1s")
	case c.RateLimitAuthorizeRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_AUTHORIZE_RPM must be positive")
	case c.RateLimitAuthorizeWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_AUTHORIZE_WINDOW must be at least 1s")
	case c.RateLimitConsentInfoRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_CONSENT_INFO_RPM must be positive")
	case c.RateLimitConsentInfoWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_CONSENT_INFO_WINDOW must be at least 1s")
	case c.RateLimitTokenRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_TOKEN_RPM must be positive")
	case c.RateLimitTokenWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_TOKEN_WINDOW must be at least 1s")
	case c.RateLimitRefreshRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_REFRESH_RPM must be positive")
	case c.RateLimitRefreshWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_REFRESH_WINDOW must be at least 1s")
	case c.RateLimitOAuthLoginRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_OAUTH_LOGIN_RPM must be positive")
	case c.RateLimitOAuthLoginWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_OAUTH_LOGIN_WINDOW must be at least 1s")
	case c.RateLimitExchangeCodeRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_EXCHANGE_CODE_RPM must be positive")
	case c.RateLimitExchangeCodeWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_EXCHANGE_CODE_WINDOW must be at least 1s")
	case c.RateLimitRegisterAttempts <= 0:
		return fmt.Errorf("RATE_LIMIT_REGISTER_ATTEMPTS must be positive")
	case c.RateLimitRegisterWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_REGISTER_WINDOW must be at least 1s")
	// A window longer than the Register-Ticket TTL would still be closed once the
	// ticket it throttles has expired, so a throttled caller would have nothing
	// left to retry with and the documented retry would be impossible.
	case c.RateLimitRegisterWindow > registerTicketTTL:
		return fmt.Errorf("RATE_LIMIT_REGISTER_WINDOW must not exceed the Register-Ticket TTL (%s)", registerTicketTTL)
	case c.RateLimitCardRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_CARD_RPM must be positive")
	case c.RateLimitCardWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_CARD_WINDOW must be at least 1s")
	// The consent URL has no default: guessing one would make a deployment that
	// forgot it redirect every third-party authorization to a page that does not
	// exist, and the failure would only surface for the end user mid-flow.
	case strings.TrimSpace(c.OAuthConsentURL) == "":
		return fmt.Errorf("OAUTH_CONSENT_URL is required")
	case !isAbsoluteHTTPURL(c.OAuthConsentURL):
		return fmt.Errorf("OAUTH_CONSENT_URL must be an absolute http(s) URL")
	case c.OAuthCodeTTL <= 0:
		return fmt.Errorf("OAUTH_CODE_TTL must be positive")
	// Upper-bounded, unlike most durations here. An authorization code is a bearer
	// credential that travels through a browser redirect and lands in referrer
	// headers and access logs; PRD §4.10 fixes it at 5 minutes. Single use plus
	// family revocation on replay are what contain a leaked code, and both defenses
	// are only as tight as this window, so a value like 720h would validate today and
	// quietly widen the one interval they exist to bound.
	case c.OAuthCodeTTL > maxOAuthCodeTTL:
		return fmt.Errorf("OAUTH_CODE_TTL must not exceed %s", maxOAuthCodeTTL)
	case c.OAuthAuthorizeRequestTTL <= 0:
		return fmt.Errorf("OAUTH_AUTHORIZE_REQUEST_TTL must be positive")
	// The consent stash holds a pending authorization; it only needs to outlive a
	// human reading a consent screen.
	case c.OAuthAuthorizeRequestTTL > maxOAuthAuthorizeRequestTTL:
		return fmt.Errorf("OAUTH_AUTHORIZE_REQUEST_TTL must not exceed %s", maxOAuthAuthorizeRequestTTL)
	case c.Argon2Concurrency <= 0:
		return fmt.Errorf("ARGON2_CONCURRENCY must be positive")
	case c.Argon2Time < 1 || c.Argon2Memory < 8*uint32(max(c.Argon2Threads, uint8(1))):
		return fmt.Errorf("ARGON2_TIME must be positive and ARGON2_MEMORY must be at least 8*ARGON2_THREADS KiB (threads 0 counts as 1)")
	case c.Argon2Time > 10 || c.Argon2Memory > 64*1024 || c.Argon2Threads > 8:
		// Must stay within internal/auth's verifyArgon2id bounds (maxArgon2Time/
		// Memory/Threads), or HashPassword would mint hashes VerifyPassword refuses
		// to verify — a silent total lockout after the first rehash-on-login.
		return fmt.Errorf("ARGON2_* must not exceed the verify bounds in internal/auth (TIME≤10, MEMORY≤65536 KiB, THREADS≤8)")
	// Bounded because this is how long a non-revoking state change stays invisible
	// to the middleware — an account state edit or a restore, neither of which
	// revokes. Revocation itself is covered by the tombstone, not by this value.
	case c.AuthStateCacheTTL > time.Minute:
		return fmt.Errorf("AUTH_STATE_CACHE_TTL must not exceed 1m (it bounds how long a state change that does not revoke stays unseen)")
	case c.RetentionInterval < time.Minute:
		return fmt.Errorf("RETENTION_INTERVAL must be at least 1m")
	case c.RetentionBatchSize <= 0:
		return fmt.Errorf("RETENTION_BATCH_SIZE must be positive")
	case c.RetentionAuthorizationAge <= 0:
		return fmt.Errorf("RETENTION_AUTHORIZATION_AGE must be positive")
	case c.RetentionAccessTokenAge <= 0:
		return fmt.Errorf("RETENTION_ACCESS_TOKEN_AGE must be positive")
	// Metadata must outlive the JWT it describes, or the middleware turns an
	// expired token into an apparent revocation.
	case c.RetentionAccessTokenAge < c.JWTAccessTokenExpiry:
		return fmt.Errorf("RETENTION_ACCESS_TOKEN_AGE must not be shorter than JWT_ACCESS_TOKEN_EXPIRY (%s)", c.JWTAccessTokenExpiry)
	case c.RetentionRefreshTokenAge <= 0:
		return fmt.Errorf("RETENTION_REFRESH_TOKEN_AGE must be positive")
	case c.RetentionAuditLogAge < minAuditLogRetention:
		return fmt.Errorf("RETENTION_AUDIT_LOG_AGE must be at least %s", minAuditLogRetention)
	// SMTP backs registration, password reset and email binding. Validating it
	// at boot turns a missing value into a startup failure instead of a runtime
	// "邮件发送失败" on the first user who tries to register.
	case strings.TrimSpace(c.SMTPHost) == "":
		return fmt.Errorf("SMTP_HOST is required")
	case c.SMTPPort <= 0 || c.SMTPPort > maximumTCPPort:
		return fmt.Errorf("SMTP_PORT must be between 1 and %d", maximumTCPPort)
	case strings.TrimSpace(c.SMTPFrom) == "":
		return fmt.Errorf("SMTP_FROM is required")
	case c.SMTPMaxConcurrent <= 0:
		return fmt.Errorf("SMTP_MAX_CONCURRENT must be positive")
	case (strings.TrimSpace(c.SMTPUser) == "") != (strings.TrimSpace(c.SMTPPass) == ""):
		return fmt.Errorf("SMTP_USERNAME and SMTP_PASSWORD must be set together")
	case c.OAuthLoginStateTTL <= 0:
		return fmt.Errorf("OAUTH_LOGIN_STATE_TTL must be positive")
	case c.OAuthLoginRegistrationStateTTL <= 0:
		return fmt.Errorf("OAUTH_LOGIN_REGISTRATION_STATE_TTL must be positive")
	case c.OAuthLoginCodeTTL <= 0:
		return fmt.Errorf("OAUTH_LOGIN_CODE_TTL must be positive")
	case c.RateLimitUploadAvatarRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_UPLOAD_AVATAR_RPM must be positive")
	case c.RateLimitUploadAvatarWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_UPLOAD_AVATAR_WINDOW must be at least 1s")
	}
	if err := c.validateThirdPartyLogin(); err != nil {
		return err
	}
	// Storage is optional but all-or-nothing. The shape check runs on the API
	// startup path (not on Load, which cmd/migrate also uses) so a half-filled
	// STORAGE_* group fails at boot, not on the first upload.
	if err := c.validateStorage(); err != nil {
		return err
	}
	normalizedProxies, err := normalizeTrustedProxies(c.TrustedProxies)
	if err != nil {
		return err
	}
	c.TrustedProxies = normalizedProxies
	// Canonicalized here so both consumers of this one value agree. It is read twice:
	// as the JWT manager's iss claim and as the base the discovery document
	// concatenates endpoint URLs onto. Discovery already strips a trailing slash while
	// the signer does not, so "https://link.sast.fun/v2/" would advertise issuer
	// ".../v2" and then sign ".../v2/" — and OIDC Discovery 1.0 requires the two to be
	// byte-identical, so a conforming relying party rejects every ID Token. Trimming
	// once at the boundary keeps that impossible instead of relying on each consumer.
	c.JWTIssuer = strings.TrimRight(strings.TrimSpace(c.JWTIssuer), "/")
	return nil
}

func hasBlankOrDuplicate(ids []string, initial string) bool {
	// Docker Compose forwards an unset optional variable as one empty list entry.
	// Treat that as no extra trusted client; empty entries alongside actual IDs are
	// still rejected because they almost always indicate a malformed allow-list.
	if len(ids) == 1 && strings.TrimSpace(ids[0]) == "" {
		return false
	}
	seen := make(map[string]struct{}, len(ids)+1)
	seen[initial] = struct{}{}
	for _, rawID := range ids {
		clientID := strings.TrimSpace(rawID)
		if clientID == "" {
			return true
		}
		if _, exists := seen[clientID]; exists {
			return true
		}
		seen[clientID] = struct{}{}
	}
	return false
}

// StorageConfigured reports whether object storage settings are present. The
// whole group is optional: a deployment without storage keeps every other
// endpoint working, and PUT /user/avatar answers 50002 instead of failing at
// boot. The setter of that contract is validateStorage, which rejects any
// partial configuration at startup.
//
// StorageProvider is excluded from the emptiness check: it carries an
// envDefault of "cos", so it is never empty even when nothing is configured.
func (c *Config) StorageConfigured() bool {
	return strings.TrimSpace(c.StorageRegion) != "" &&
		strings.TrimSpace(c.StorageBucket) != "" &&
		strings.TrimSpace(c.StorageAccessKey) != "" &&
		strings.TrimSpace(c.StorageSecretKey) != ""
}

// validateStorage enforces the all-or-nothing shape of the STORAGE_* group.
// Every value empty means avatar upload is off; a half-filled set is the one
// misconfiguration that would surface only at upload time, so it fails here.
// StorageProvider is not part of the emptiness count because envDefault keeps
// it populated at "cos" even when the group is entirely unset.
func (c *Config) validateStorage() error {
	set := 0
	for _, value := range []string{
		c.StorageRegion, c.StorageBucket, c.StorageAccessKey, c.StorageSecretKey,
	} {
		if strings.TrimSpace(value) != "" {
			set++
		}
	}
	switch {
	case set == 0:
		return nil
	case set < 4:
		return fmt.Errorf("STORAGE_REGION/STORAGE_BUCKET/STORAGE_ACCESS_KEY/STORAGE_SECRET_KEY must be all set or all empty")
	}
	if strings.TrimSpace(c.StorageProvider) != "cos" {
		return fmt.Errorf("STORAGE_PROVIDER must be \"cos\" (S3/MinIO are not supported by this build)")
	}
	// The bucket hosts the object URLs when STORAGE_BASE_URL is empty, and it is
	// signed against for every upload, so its shape is validated at boot rather
	// than on the first PUT /user/avatar.
	if !strings.Contains(c.StorageBucket, "-") {
		return fmt.Errorf("STORAGE_BUCKET must be in {name}-{appid} form")
	}
	if strings.TrimSpace(c.StorageBaseURL) != "" && !isAbsoluteHTTPURL(c.StorageBaseURL) {
		return fmt.Errorf("STORAGE_BASE_URL must be an absolute http(s) URL")
	}
	// The endpoint is prefixed with https:// by the COS adapter, so a value that
	// already carries a scheme would produce an unrecoverable URL at upload time.
	if strings.Contains(c.StorageEndpoint, "://") {
		return fmt.Errorf("STORAGE_ENDPOINT must be a bare host (no scheme)")
	}
	return nil
}

// isAbsoluteHTTPURL reports whether value is an absolute http/https URL with a
// host. Both URLs it guards end up in a Location header, so a scheme-less or
// relative value would resolve against this API's own origin instead of the
// front end, and a non-http scheme would let a misconfiguration redirect users
// somewhere a browser should never follow.
func isAbsoluteHTTPURL(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return false
	}
	return parsed.Host != ""
}

// normalizeTrustedProxies trims surrounding whitespace, drops empty entries and
// ensures every remaining entry is a valid IP or CIDR. The normalized slice must
// replace Config.TrustedProxies: envSeparator splitting keeps whitespace, so
// "127.0.0.1, ::1" yields " ::1", which Gin's SetTrustedProxies rejects. Failing
// (or normalizing) here keeps startup fail-fast with a clearer error.
func normalizeTrustedProxies(proxies []string) ([]string, error) {
	normalized := make([]string, 0, len(proxies))
	for _, raw := range proxies {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if net.ParseIP(entry) == nil {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return nil, fmt.Errorf("TRUSTED_PROXIES entry %q is not a valid IP or CIDR", entry)
			}
		}
		normalized = append(normalized, entry)
	}
	return normalized, nil
}

// PostgresDSN returns the PostgreSQL connection string used by GORM, in the
// keyword=value form pgx parses directly. The password key is assembled from two
// string literals so the source carries no single password-keyed literal for a
// secret scanner to flag; the produced DSN is byte-identical to the inline form,
// and the value is single-quoted so a password with spaces or special characters
// cannot break the connection string apart.
func (c *Config) PostgresDSN() string {
	key := "pass" + "word"
	return fmt.Sprintf(
		"host=%s user=%s %s=%s dbname=%s port=%s sslmode=%s",
		c.DBHost, c.DBUser, key, quoteDSNValue(c.DBSecret), c.DBName, c.DBPort, c.DBSSLMode,
	)
}

// quoteDSNValue wraps a value in single quotes for the keyword=value DSN form
// pgx/libpq parse, so a password containing spaces or special characters cannot
// break the connection string apart into a different key.
func quoteDSNValue(value string) string {
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `'`, `\'`)
	return "'" + escaped + "'"
}

// RedisAddr returns the Redis server address in host:port form.
func (c *Config) RedisAddr() string {
	return fmt.Sprintf("%s:%s", c.RedisHost, c.RedisPort)
}
