// Package config loads application configuration from environment variables.
package config

import (
	"fmt"
	"net"
	"net/url"
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
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`

	DBHost     string `env:"DB_HOST" envDefault:"localhost"`
	DBPort     string `env:"DB_PORT" envDefault:"5432"`
	DBUser     string `env:"DB_USER"`
	DBPassword string `env:"DB_PASSWORD"`
	DBName     string `env:"DB_NAME"`
	DBSSLMode  string `env:"DB_SSLMODE" envDefault:"disable"`

	RedisHost      string `env:"REDIS_HOST" envDefault:"localhost"`
	RedisPort      string `env:"REDIS_PORT" envDefault:"6379"`
	RedisPassword  string `env:"REDIS_PASSWORD" envDefault:""`
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
	// OAuthCardBaseURL prefixes the OIDC profile claim, which points at a user's
	// public display card. It is not derived from JWT_ISSUER: the issuer carries the
	// API's /v2 base path while the card is a front-end route without it.
	OAuthCardBaseURL string `env:"OAUTH_CARD_BASE_URL" envDefault:"https://link.sast.fun/card"`
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

	InternalOAuthClientID    string        `env:"INTERNAL_OAUTH_CLIENT_ID" envDefault:"sast-link-web"`
	CORSAllowedOrigins       []string      `env:"CORS_ALLOWED_ORIGINS" envSeparator:","`
	TrustedProxies           []string      `env:"TRUSTED_PROXIES" envSeparator:"," envDefault:"127.0.0.1,::1"`
	HSTSMaxAge               int           `env:"HSTS_MAX_AGE" envDefault:"31536000"`
	RateLimitLoginRPM        int           `env:"RATE_LIMIT_LOGIN_RPM" envDefault:"5"`
	RateLimitLoginWindow     time.Duration `env:"RATE_LIMIT_LOGIN_WINDOW" envDefault:"15m"`
	RateLimitSendEmailRPM    int           `env:"RATE_LIMIT_SEND_EMAIL_RPM" envDefault:"3"`
	RateLimitSendEmailIPRPM  int           `env:"RATE_LIMIT_SEND_EMAIL_IP_RPM" envDefault:"10"`
	RateLimitSendEmailWindow time.Duration `env:"RATE_LIMIT_SEND_EMAIL_WINDOW" envDefault:"60s"`
	LoginFailureLimit        int           `env:"LOGIN_FAILURE_LIMIT" envDefault:"10"`
	LoginFailureWindow       time.Duration `env:"LOGIN_FAILURE_WINDOW" envDefault:"15m"`
	// Unbind throttling is per caller, not per address: keying by provider_id let
	// one user's unbind lock out a different user who later bound the same
	// address. Fail-open, since PostgreSQL owns the binding state and is also the
	// serialization point for concurrent deletes of one record.
	RateLimitUnbindRPM    int           `env:"RATE_LIMIT_UNBIND_RPM" envDefault:"3"`
	RateLimitUnbindWindow time.Duration `env:"RATE_LIMIT_UNBIND_WINDOW" envDefault:"60s"`
	// Throttles GET /oauth/authorize per caller IP. The endpoint is
	// unauthenticated and writes a Redis stash per call, so without a limit anyone
	// could fill the keyspace. Fail-open, per PRD §6.0.
	RateLimitAuthorizeRPM    int           `env:"RATE_LIMIT_AUTHORIZE_RPM" envDefault:"20"`
	RateLimitAuthorizeWindow time.Duration `env:"RATE_LIMIT_AUTHORIZE_WINDOW" envDefault:"60s"`
	// Throttles POST /oauth/token and POST /oauth/revoke per caller IP. Both check
	// client credentials and presented tokens, so an unlimited rate means unlimited
	// credential attempts. Set higher than the authorize limit: one authorization
	// legitimately produces a token request plus periodic refreshes, and several
	// clients can share an egress IP. Fail-open, per PRD §6.0.
	RateLimitTokenRPM    int           `env:"RATE_LIMIT_TOKEN_RPM" envDefault:"60"`
	RateLimitTokenWindow time.Duration `env:"RATE_LIMIT_TOKEN_WINDOW" envDefault:"60s"`
	// Throttles GET /oauth/github and GET /oauth/lark per caller IP. Same shape as
	// the authorize endpoint above — unauthenticated, and every call writes one
	// oauth_state key — so it carries the same cap. Fail-open, per PRD §6.0.
	RateLimitOAuthLoginRPM    int           `env:"RATE_LIMIT_OAUTH_LOGIN_RPM" envDefault:"20"`
	RateLimitOAuthLoginWindow time.Duration `env:"RATE_LIMIT_OAUTH_LOGIN_WINDOW" envDefault:"60s"`
	// Throttles POST /oauth/exchange-code per caller IP. Unauthenticated by
	// design — redeeming a login_code is how a session is obtained — so without a cap
	// the code space can be probed for free. Higher than the login cap: one login
	// legitimately redeems once, but a shared egress IP multiplies that.
	RateLimitExchangeCodeRPM    int           `env:"RATE_LIMIT_EXCHANGE_CODE_RPM" envDefault:"30"`
	RateLimitExchangeCodeWindow time.Duration `env:"RATE_LIMIT_EXCHANGE_CODE_WINDOW" envDefault:"60s"`
	// Throttles POST /auth/register per Register-Ticket, not per IP. Each accepted
	// call runs one PBKDF2-SHA512 derivation at 600k iterations, so what needs
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

	// PasswordHashMaxConcurrent caps simultaneous PBKDF2 derivations. A burst
	// beyond this queues at the hasher instead of saturating every CPU core.
	PasswordHashMaxConcurrent int `env:"PASSWORD_HASH_MAX_CONCURRENT" envDefault:"64"`

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
}

// Load parses configuration from environment variables and validates required fields.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	switch {
	case c.DBUser == "":
		return fmt.Errorf("DB_USER is required")
	case c.DBPassword == "":
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
	case c.RateLimitAuthorizeRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_AUTHORIZE_RPM must be positive")
	case c.RateLimitAuthorizeWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_AUTHORIZE_WINDOW must be at least 1s")
	case c.RateLimitTokenRPM <= 0:
		return fmt.Errorf("RATE_LIMIT_TOKEN_RPM must be positive")
	case c.RateLimitTokenWindow < time.Second:
		return fmt.Errorf("RATE_LIMIT_TOKEN_WINDOW must be at least 1s")
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
	case !isAbsoluteHTTPURL(c.OAuthCardBaseURL):
		return fmt.Errorf("OAUTH_CARD_BASE_URL must be an absolute http(s) URL")
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
	case c.PasswordHashMaxConcurrent <= 0:
		return fmt.Errorf("PASSWORD_HASH_MAX_CONCURRENT must be positive")
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
	case c.OAuthLoginStateTTL <= 0:
		return fmt.Errorf("OAUTH_LOGIN_STATE_TTL must be positive")
	case c.OAuthLoginRegistrationStateTTL <= 0:
		return fmt.Errorf("OAUTH_LOGIN_REGISTRATION_STATE_TTL must be positive")
	case c.OAuthLoginCodeTTL <= 0:
		return fmt.Errorf("OAUTH_LOGIN_CODE_TTL must be positive")
	}
	if err := c.validateThirdPartyLogin(); err != nil {
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

// PostgresDSN returns the PostgreSQL connection string used by GORM.
func (c *Config) PostgresDSN() string {
	return fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		c.DBHost, c.DBUser, c.DBPassword, c.DBName, c.DBPort, c.DBSSLMode,
	)
}

// RedisAddr returns the Redis server address in host:port form.
func (c *Config) RedisAddr() string {
	return fmt.Sprintf("%s:%s", c.RedisHost, c.RedisPort)
}
