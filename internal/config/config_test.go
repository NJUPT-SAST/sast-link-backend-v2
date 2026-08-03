package config

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web"
)

func setConfigEnv(t *testing.T, dbUser, dbPassword, dbName string) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("APP_PORT", "9090")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("DB_HOST", "pg")
	t.Setenv("DB_PORT", "5433")
	t.Setenv("DB_USER", dbUser)
	t.Setenv("DB_PASSWORD", dbPassword)
	t.Setenv("DB_NAME", dbName)
	t.Setenv("DB_SSLMODE", "require")
	t.Setenv("REDIS_HOST", "redis")
	t.Setenv("REDIS_PORT", "6380")
	t.Setenv("REDIS_PASSWORD", "secret")
	t.Setenv("REDIS_DB", "2")
	t.Setenv("REDIS_KEY_PREFIX", "sastlink:test")
	t.Setenv("JWT_SECRET_KEY", "active-rsa-private-key-pem")
	t.Setenv("JWT_SECRET_KEY_PREV", "previous-rsa-private-key-pem")
	t.Setenv("JWT_ACTIVE_KID", "active-kid")
	t.Setenv("JWT_PREVIOUS_KID", "previous-kid")
	t.Setenv("JWT_ISSUER", "https://issuer.example/v2")
	t.Setenv("JWT_AUDIENCE", "test-audience")
	t.Setenv("JWT_ACCESS_TOKEN_EXPIRY", "15m")
	t.Setenv("JWT_REFRESH_TOKEN_EXPIRY", "720h")
	t.Setenv("REFRESH_TOKEN_HMAC_SECRET", "0123456789abcdef0123456789abcdef")
	t.Setenv("SMTP_HOST", "smtp.example.test")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_FROM", "noreply@example.test")
	t.Setenv("OAUTH_CONSENT_URL", "https://link.example.test/oauth/consent")
}

// Retention windows bound how long dead rows survive, but two of them are floors
// rather than free knobs: access-token metadata must outlive the JWT it describes,
// and audit history may not be trimmed below what PRD §9 promises.
func TestValidateAPIAuthRejectsBadRetentionSettings(t *testing.T) {
	for _, test := range []struct{ key, value, want string }{
		{"RETENTION_INTERVAL", "30s", "RETENTION_INTERVAL must be at least 1m"},
		{"RETENTION_BATCH_SIZE", "0", "RETENTION_BATCH_SIZE must be positive"},
		{"RETENTION_AUTHORIZATION_AGE", "0", "RETENTION_AUTHORIZATION_AGE must be positive"},
		{"RETENTION_ACCESS_TOKEN_AGE", "0", "RETENTION_ACCESS_TOKEN_AGE must be positive"},
		{"RETENTION_ACCESS_TOKEN_AGE", "5m", "RETENTION_ACCESS_TOKEN_AGE must not be shorter than JWT_ACCESS_TOKEN_EXPIRY"},
		{"RETENTION_REFRESH_TOKEN_AGE", "0", "RETENTION_REFRESH_TOKEN_AGE must be positive"},
		{"RETENTION_AUDIT_LOG_AGE", "24h", "RETENTION_AUDIT_LOG_AGE must be at least"},
		{"RETENTION_AUDIT_LOG_AGE", "719h", "RETENTION_AUDIT_LOG_AGE must be at least"},
	} {
		t.Run(test.key+"="+test.value, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv(test.key, test.value)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if err := cfg.ValidateAPIAuth(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateAPIAuth() error = %v, want %q", err, test.want)
			}
		})
	}
}

// Audit history is operational rather than compliance-bound, so the 90-day PRD §9
// figure is the default, not a hard minimum: a deployment may keep more, or trim
// below it down to the sanity floor.
func TestValidateAPIAuthAllowsAuditRetentionAboveFloor(t *testing.T) {
	for _, value := range []string{
		"8760h", // a year: more history than the default
		"2160h", // the 90-day default
		"720h",  // 30 days: the floor itself
		"1000h", // between the floor and the default
	} {
		t.Run(value, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv("RETENTION_AUDIT_LOG_AGE", value)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if err := cfg.ValidateAPIAuth(); err != nil {
				t.Fatalf("ValidateAPIAuth() error = %v, want nil for %q", err, value)
			}
		})
	}
}

// Every default must satisfy its own floor, or a deployment that sets none of
// these fails to start.
func TestDefaultRetentionSettingsValidate(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.RetentionAuditLogAge < minAuditLogRetention {
		t.Fatalf("default RETENTION_AUDIT_LOG_AGE = %s, want >= %s", cfg.RetentionAuditLogAge, minAuditLogRetention)
	}
	if cfg.RetentionAccessTokenAge < cfg.JWTAccessTokenExpiry {
		t.Fatalf("default RETENTION_ACCESS_TOKEN_AGE = %s, want >= JWT_ACCESS_TOKEN_EXPIRY %s",
			cfg.RetentionAccessTokenAge, cfg.JWTAccessTokenExpiry)
	}
	if err := cfg.ValidateAPIAuth(); err != nil {
		t.Fatalf("ValidateAPIAuth() with defaults = %v, want nil", err)
	}
}

func TestLoadMissingRequiredFields(t *testing.T) {
	setConfigEnv(t, "", "", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing required database config")
	}
}

func TestLoadValidConfig(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.AppEnv != "test" {
		t.Errorf("AppEnv = %q, want test", cfg.AppEnv)
	}
	if cfg.AppPort != "9090" {
		t.Errorf("AppPort = %q, want 9090", cfg.AppPort)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
	}

	dsn := cfg.PostgresDSN()
	if !strings.Contains(dsn, "host=pg") {
		t.Errorf("PostgresDSN missing host: %s", dsn)
	}
	if !strings.Contains(dsn, "port=5433") {
		t.Errorf("PostgresDSN missing port: %s", dsn)
	}

	if cfg.RedisAddr() != "redis:6380" {
		t.Errorf("RedisAddr = %q, want redis:6380", cfg.RedisAddr())
	}
	if cfg.RedisPassword != "secret" {
		t.Errorf("RedisPassword = %q, want secret", cfg.RedisPassword)
	}
	if cfg.RedisDB != 2 {
		t.Errorf("RedisDB = %d, want 2", cfg.RedisDB)
	}
	if cfg.RedisKeyPrefix != "sastlink:test" {
		t.Errorf("RedisKeyPrefix = %q, want sastlink:test", cfg.RedisKeyPrefix)
	}

	if cfg.JWTSecretKey != "active-rsa-private-key-pem" {
		t.Errorf("JWTSecretKey = %q, want active-rsa-private-key-pem", cfg.JWTSecretKey)
	}
	if cfg.JWTSecretKeyPrev != "previous-rsa-private-key-pem" {
		t.Errorf("JWTSecretKeyPrev = %q, want previous-rsa-private-key-pem", cfg.JWTSecretKeyPrev)
	}
	if cfg.JWTActiveKID != "active-kid" {
		t.Errorf("JWTActiveKID = %q, want active-kid", cfg.JWTActiveKID)
	}
	if cfg.JWTPreviousKID != "previous-kid" {
		t.Errorf("JWTPreviousKID = %q, want previous-kid", cfg.JWTPreviousKID)
	}
	if cfg.JWTIssuer != "https://issuer.example/v2" {
		t.Errorf("JWTIssuer = %q, want https://issuer.example/v2", cfg.JWTIssuer)
	}
	if cfg.JWTAudience != "test-audience" {
		t.Errorf("JWTAudience = %q, want test-audience", cfg.JWTAudience)
	}
	if cfg.JWTAccessTokenExpiry != 15*time.Minute {
		t.Errorf("JWTAccessTokenExpiry = %s, want 15m", cfg.JWTAccessTokenExpiry)
	}
	if cfg.JWTRefreshTokenExpiry != 720*time.Hour {
		t.Errorf("JWTRefreshTokenExpiry = %s, want 720h", cfg.JWTRefreshTokenExpiry)
	}
	if cfg.RefreshTokenHMACSecret != "0123456789abcdef0123456789abcdef" {
		t.Errorf("RefreshTokenHMACSecret = %q, want 0123456789abcdef0123456789abcdef", cfg.RefreshTokenHMACSecret)
	}
	if cfg.InternalOAuthClientID != "sast-link-web" {
		t.Errorf("InternalOAuthClientID = %q, want sast-link-web", cfg.InternalOAuthClientID)
	}
	if cfg.RateLimitLoginRPM != 5 {
		t.Errorf("RateLimitLoginRPM = %d, want 5", cfg.RateLimitLoginRPM)
	}
	if cfg.RateLimitLoginWindow != 15*time.Minute {
		t.Errorf("RateLimitLoginWindow = %s, want 15m", cfg.RateLimitLoginWindow)
	}
	if cfg.LoginFailureLimit != 10 {
		t.Errorf("LoginFailureLimit = %d, want 10", cfg.LoginFailureLimit)
	}
	if cfg.LoginFailureWindow != 15*time.Minute {
		t.Errorf("LoginFailureWindow = %s, want 15m", cfg.LoginFailureWindow)
	}
	if cfg.RateLimitUnbindRPM != 3 {
		t.Errorf("RateLimitUnbindRPM = %d, want 3", cfg.RateLimitUnbindRPM)
	}
	if cfg.RateLimitUnbindWindow != time.Minute {
		t.Errorf("RateLimitUnbindWindow = %s, want 60s", cfg.RateLimitUnbindWindow)
	}
	if cfg.RateLimitDeviceRPM != 3 {
		t.Errorf("RateLimitDeviceRPM = %d, want 3", cfg.RateLimitDeviceRPM)
	}
	if cfg.RateLimitDeviceWindow != time.Minute {
		t.Errorf("RateLimitDeviceWindow = %s, want 60s", cfg.RateLimitDeviceWindow)
	}
}

func TestLoadAllowsMigrateWithoutCryptoMaterial(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("JWT_SECRET_KEY", "")
	t.Setenv("JWT_ACTIVE_KID", "")
	t.Setenv("REFRESH_TOKEN_HMAC_SECRET", "")
	t.Setenv("JWT_ACCESS_TOKEN_EXPIRY", "0")
	t.Setenv("JWT_REFRESH_TOKEN_EXPIRY", "0")

	if _, err := Load(); err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
}

func TestValidateAPIAuthRejectsMissingCryptoMaterial(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("JWT_SECRET_KEY", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	err = cfg.ValidateAPIAuth()
	if err == nil || !strings.Contains(err.Error(), "JWT_SECRET_KEY is required") {
		t.Fatalf("ValidateAPIAuth() error = %v, want JWT_SECRET_KEY required validation", err)
	}
}

func TestValidateAPIAuthRejectsShortRefreshHMACSecret(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("REFRESH_TOKEN_HMAC_SECRET", "too-short")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	err = cfg.ValidateAPIAuth()
	if err == nil || !strings.Contains(err.Error(), "REFRESH_TOKEN_HMAC_SECRET must be at least 32 bytes") {
		t.Fatalf("ValidateAPIAuth() error = %v, want HMAC length validation", err)
	}
}

func TestValidateAPIAuthRejectsNonPositiveAccessTokenExpiry(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("JWT_ACCESS_TOKEN_EXPIRY", "0")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	err = cfg.ValidateAPIAuth()
	if err == nil || !strings.Contains(err.Error(), "JWT_ACCESS_TOKEN_EXPIRY must be positive") {
		t.Fatalf("ValidateAPIAuth() error = %v, want JWT_ACCESS_TOKEN_EXPIRY positive validation", err)
	}
}

func TestValidateAPIAuthRejectsNonPositiveRefreshTokenExpiry(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("JWT_REFRESH_TOKEN_EXPIRY", "-1h")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	err = cfg.ValidateAPIAuth()
	if err == nil || !strings.Contains(err.Error(), "JWT_REFRESH_TOKEN_EXPIRY must be positive") {
		t.Fatalf("ValidateAPIAuth() error = %v, want JWT_REFRESH_TOKEN_EXPIRY positive validation", err)
	}
}

func TestValidateAPIAuthRejectsNonPositiveRateSettings(t *testing.T) {
	cases := []struct {
		name    string
		envName string
		value   string
		want    string
	}{
		{name: "login rpm", envName: "RATE_LIMIT_LOGIN_RPM", value: "0", want: "RATE_LIMIT_LOGIN_RPM must be positive"},
		{name: "login window", envName: "RATE_LIMIT_LOGIN_WINDOW", value: "500ms", want: "RATE_LIMIT_LOGIN_WINDOW must be at least 1s"},
		{name: "failure limit", envName: "LOGIN_FAILURE_LIMIT", value: "0", want: "LOGIN_FAILURE_LIMIT must be positive"},
		{name: "failure window", envName: "LOGIN_FAILURE_WINDOW", value: "0", want: "LOGIN_FAILURE_WINDOW must be positive"},
		{name: "unbind rpm", envName: "RATE_LIMIT_UNBIND_RPM", value: "0", want: "RATE_LIMIT_UNBIND_RPM must be positive"},
		{name: "unbind window", envName: "RATE_LIMIT_UNBIND_WINDOW", value: "500ms", want: "RATE_LIMIT_UNBIND_WINDOW must be at least 1s"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv(tc.envName, tc.value)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateAPIAuth() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateAPIAuthAllowsOneSecondRateWindow(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("RATE_LIMIT_LOGIN_WINDOW", "1s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err := cfg.ValidateAPIAuth(); err != nil {
		t.Fatalf("ValidateAPIAuth() error = %v, want nil", err)
	}
}

func TestValidateAPIAuthAcceptsValidTrustedProxies(t *testing.T) {
	cases := []struct {
		name   string
		values string
	}{
		{name: "loopback IPs", values: "127.0.0.1,::1"},
		{name: "CIDR ranges", values: "10.0.0.0/8,172.16.0.0/12,::1/128"},
		{name: "mixed IP and CIDR", values: "127.0.0.1,10.0.0.0/8"},
		{name: "single IPv4", values: "203.0.113.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv("TRUSTED_PROXIES", tc.values)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if err := cfg.ValidateAPIAuth(); err != nil {
				t.Fatalf("ValidateAPIAuth() error = %v, want nil for %q", err, tc.values)
			}
		})
	}
}

func TestValidateAPIAuthNormalizesTrustedProxies(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  []string
	}{
		{name: "spaces after separator", value: "127.0.0.1, ::1", want: []string{"127.0.0.1", "::1"}},
		{name: "empty entries", value: "127.0.0.1,,::1", want: []string{"127.0.0.1", "::1"}},
		{name: "trailing separator", value: "127.0.0.1,", want: []string{"127.0.0.1"}},
		{name: "padded CIDR", value: " 10.0.0.0/8 ", want: []string{"10.0.0.0/8"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv("TRUSTED_PROXIES", tc.value)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if validateErr := cfg.ValidateAPIAuth(); validateErr != nil {
				t.Fatalf("ValidateAPIAuth() error = %v, want nil for %q", validateErr, tc.value)
			}
			if !slices.Equal(cfg.TrustedProxies, tc.want) {
				t.Fatalf("TrustedProxies = %#v, want %#v", cfg.TrustedProxies, tc.want)
			}
			// Gin must accept exactly what validation approved.
			if _, routerErr := web.NewRouter(nil, cfg.TrustedProxies, cfg.HSTSMaxAge); routerErr != nil {
				t.Fatalf("NewRouter() error = %v, want nil for normalized %#v", routerErr, cfg.TrustedProxies)
			}
		})
	}
}

func TestValidateAPIAuthRejectsWeakHSTSMaxAge(t *testing.T) {
	for _, value := range []string{"0", "-1", "1", "86400", "31535999"} {
		t.Run(value, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv("HSTS_MAX_AGE", value)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), "HSTS_MAX_AGE") {
				t.Fatalf("ValidateAPIAuth() error = %v, want HSTS_MAX_AGE validation for %q", err, value)
			}
		})
	}
}

// SMTP is validated at boot so a missing value fails startup instead of
// surfacing as a runtime mail failure for the first user who tries to register.
func TestValidateAPIAuthRejectsIncompleteSMTP(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		value   string
		wantKey string
	}{
		{name: "missing host", key: "SMTP_HOST", value: "", wantKey: "SMTP_HOST"},
		{name: "blank host", key: "SMTP_HOST", value: "   ", wantKey: "SMTP_HOST"},
		{name: "missing from", key: "SMTP_FROM", value: "", wantKey: "SMTP_FROM"},
		{name: "zero port", key: "SMTP_PORT", value: "0", wantKey: "SMTP_PORT"},
		{name: "port above range", key: "SMTP_PORT", value: "70000", wantKey: "SMTP_PORT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv(tc.key, tc.value)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), tc.wantKey) {
				t.Fatalf("ValidateAPIAuth() error = %v, want %s validation", err, tc.wantKey)
			}
		})
	}
}

func TestValidateAPIAuthAcceptsHSTSMaxAgeAtMinimum(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("HSTS_MAX_AGE", "31536000")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if validateErr := cfg.ValidateAPIAuth(); validateErr != nil {
		t.Fatalf("ValidateAPIAuth() error = %v, want nil", validateErr)
	}
}

func TestValidateAPIAuthRejectsInvalidTrustedProxies(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{name: "not an IP or CIDR", value: "not-a-proxy"},
		{name: "hostname", value: "proxy.example.com"},
		{name: "garbled CIDR", value: "10.0.0.0/33"},
		{name: "port suffix", value: "127.0.0.1:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv("TRUSTED_PROXIES", "127.0.0.1,"+tc.value)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), "TRUSTED_PROXIES") {
				t.Fatalf("ValidateAPIAuth() error = %v, want TRUSTED_PROXIES validation for %q", err, tc.value)
			}
		})
	}
}

func TestLoadRejectsPreviousKeyWithoutPreviousKID(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("JWT_PREVIOUS_KID", "")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "JWT_SECRET_KEY_PREV and JWT_PREVIOUS_KID must be both set or both empty") {
		t.Fatalf("Load() error = %v, want previous key/kid pair validation", err)
	}
}

func TestLoadRejectsWhitespacePreviousKIDWithPreviousKey(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("JWT_PREVIOUS_KID", "   ")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "JWT_SECRET_KEY_PREV and JWT_PREVIOUS_KID must be both set or both empty") {
		t.Fatalf("Load() error = %v, want trimmed previous key/kid pair validation", err)
	}
}

func TestLoadRejectsPreviousKIDWithoutPreviousKey(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("JWT_SECRET_KEY_PREV", "")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "JWT_SECRET_KEY_PREV and JWT_PREVIOUS_KID must be both set or both empty") {
		t.Fatalf("Load() error = %v, want previous key/kid pair validation", err)
	}
}

// JWT_ISSUER is both the iss claim and the base every OIDC discovery endpoint URL
// is built from, so a scheme-less value would publish endpoint URLs no relying
// party can resolve — a failure visible only to third-party integrators.
func TestValidateAPIAuthRejectsRelativeJWTIssuer(t *testing.T) {
	for _, issuer := range []string{"link.sast.fun", "/v2", "ftp://link.sast.fun"} {
		t.Run(issuer, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv("JWT_ISSUER", issuer)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), "JWT_ISSUER must be an absolute http(s) URL") {
				t.Fatalf("ValidateAPIAuth() error = %v, want JWT_ISSUER URL validation", err)
			}
		})
	}
}

// JWT_ISSUER is canonicalized without its trailing slash, because the value is read
// twice: as the iss claim the JWT manager signs, and as the base the discovery
// document builds endpoint URLs from. Discovery strips a trailing slash and the
// signer does not, so an untrimmed "…/v2/" would advertise issuer "…/v2" and sign
// "…/v2/" — OIDC Discovery 1.0 requires them byte-identical, so a conforming relying
// party would reject every ID Token this service issues.
func TestValidateAPIAuthCanonicalizesJWTIssuer(t *testing.T) {
	for _, test := range []struct{ given, want string }{
		{"https://link.sast.fun/v2/", "https://link.sast.fun/v2"},
		{"https://link.sast.fun/v2///", "https://link.sast.fun/v2"},
		{"  https://link.sast.fun/v2  ", "https://link.sast.fun/v2"},
		{"https://link.sast.fun/v2", "https://link.sast.fun/v2"},
	} {
		t.Run(test.given, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv("JWT_ISSUER", test.given)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if err := cfg.ValidateAPIAuth(); err != nil {
				t.Fatalf("ValidateAPIAuth() error = %v", err)
			}
			if cfg.JWTIssuer != test.want {
				t.Fatalf("JWTIssuer = %q, want %q", cfg.JWTIssuer, test.want)
			}
		})
	}
}

// An authorization code is a bearer credential that travels through a browser
// redirect. Single use plus family revocation on replay are only as tight as this
// window, so an unbounded TTL would quietly widen the interval they exist to bound.
func TestValidateAPIAuthRejectsOverlongOAuthTTLs(t *testing.T) {
	for _, test := range []struct{ key, value, want string }{
		{"OAUTH_CODE_TTL", "720h", "OAUTH_CODE_TTL must not exceed"},
		{"OAUTH_AUTHORIZE_REQUEST_TTL", "48h", "OAUTH_AUTHORIZE_REQUEST_TTL must not exceed"},
	} {
		t.Run(test.key, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv(test.key, test.value)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateAPIAuth() error = %v, want %q", err, test.want)
			}
		})
	}
}

// The register limiter is keyed by Register-Ticket, so a window outliving the
// ticket's TTL would still be closed once the ticket expired — the throttled
// caller would have nothing left to retry with. Caught at startup rather than
// discovered by a user who cannot register.
func TestValidateAPIAuthRejectsRegisterWindowLongerThanTicketTTL(t *testing.T) {
	for _, test := range []struct{ key, value, want string }{
		{"RATE_LIMIT_REGISTER_ATTEMPTS", "0", "RATE_LIMIT_REGISTER_ATTEMPTS must be positive"},
		{"RATE_LIMIT_REGISTER_WINDOW", "100ms", "RATE_LIMIT_REGISTER_WINDOW must be at least 1s"},
		{"RATE_LIMIT_REGISTER_WINDOW", "1h", "RATE_LIMIT_REGISTER_WINDOW must not exceed the Register-Ticket TTL"},
	} {
		t.Run(test.key+"="+test.value, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv(test.key, test.value)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if err := cfg.ValidateAPIAuth(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateAPIAuth() error = %v, want %q", err, test.want)
			}
		})
	}
}

// The default must satisfy its own ceiling, or every deployment that does not set
// the variable fails to start.
func TestDefaultRegisterWindowFitsTicketTTL(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.RateLimitRegisterWindow > registerTicketTTL {
		t.Fatalf("default RATE_LIMIT_REGISTER_WINDOW = %s, want <= ticket TTL %s",
			cfg.RateLimitRegisterWindow, registerTicketTTL)
	}
	if err := cfg.ValidateAPIAuth(); err != nil {
		t.Fatalf("ValidateAPIAuth() with defaults = %v, want nil", err)
	}
}

// The token endpoint's limiter is what keeps client_secret and refresh_token
// guessing bounded, so a misconfigured value must fail at startup.
func TestValidateAPIAuthRejectsBadTokenRateLimit(t *testing.T) {
	for _, test := range []struct{ key, value, want string }{
		{"RATE_LIMIT_TOKEN_RPM", "0", "RATE_LIMIT_TOKEN_RPM must be positive"},
		{"RATE_LIMIT_TOKEN_WINDOW", "100ms", "RATE_LIMIT_TOKEN_WINDOW must be at least 1s"},
	} {
		t.Run(test.key, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv(test.key, test.value)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateAPIAuth() error = %v, want %q", err, test.want)
			}
		})
	}
}

func setStorageEnv(t *testing.T) {
	t.Setenv("STORAGE_PROVIDER", "cos")
	t.Setenv("STORAGE_REGION", "ap-nanjing")
	t.Setenv("STORAGE_BUCKET", "sast-link-1250000000")
	t.Setenv("STORAGE_ACCESS_KEY", "AKIDtest")
	t.Setenv("STORAGE_SECRET_KEY", "secret")
}

// A partially filled STORAGE_* group is the misconfiguration that would only
// surface at upload time, so it must fail at boot.
func TestLoadRejectsPartialStorageConfiguration(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("STORAGE_REGION", "ap-nanjing")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err = cfg.ValidateAPIAuth(); err == nil || !strings.Contains(err.Error(), "must be all set or all empty") {
		t.Fatalf("ValidateAPIAuth() error = %v, want partial-storage rejection", err)
	}
}

func TestLoadRejectsNonCosStorageProvider(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	setStorageEnv(t)
	t.Setenv("STORAGE_PROVIDER", "minio")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err = cfg.ValidateAPIAuth(); err == nil || !strings.Contains(err.Error(), "STORAGE_PROVIDER must be") {
		t.Fatalf("ValidateAPIAuth() error = %v, want provider rejection", err)
	}
}

func TestLoadRejectsBucketWithoutAppID(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	setStorageEnv(t)
	t.Setenv("STORAGE_BUCKET", "sastlink")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err = cfg.ValidateAPIAuth(); err == nil || !strings.Contains(err.Error(), "{name}-{appid}") {
		t.Fatalf("ValidateAPIAuth() error = %v, want bucket-shape rejection", err)
	}
}

func TestLoadRejectsBadStorageBaseURL(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	setStorageEnv(t)
	t.Setenv("STORAGE_BASE_URL", "cdn.example.com/avatars")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err = cfg.ValidateAPIAuth(); err == nil || !strings.Contains(err.Error(), "STORAGE_BASE_URL must be") {
		t.Fatalf("ValidateAPIAuth() error = %v, want base URL rejection", err)
	}
}

// The whole group empty is a legitimate deployment shape: every other endpoint
// keeps working and avatar upload answers 50002.
func TestLoadAllowsEmptyStorageConfiguration(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.StorageConfigured() {
		t.Fatal("StorageConfigured() = true, want false with empty STORAGE_*")
	}
}

func TestLoadAcceptsFullStorageConfiguration(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	setStorageEnv(t)
	t.Setenv("STORAGE_BASE_URL", "https://cdn.sast.fun")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.StorageConfigured() {
		t.Fatal("StorageConfigured() = false, want true with full STORAGE_*")
	}
	// Content review is on by default (fail-closed), per the PLAN decision.
	if !cfg.StorageAuditEnabled {
		t.Fatal("StorageAuditEnabled = false, want true by default")
	}
}

func TestValidateAPIAuthRejectsBadAvatarRateLimit(t *testing.T) {
	for _, test := range []struct{ key, value, want string }{
		{"RATE_LIMIT_UPLOAD_AVATAR_RPM", "0", "RATE_LIMIT_UPLOAD_AVATAR_RPM must be positive"},
		{"RATE_LIMIT_UPLOAD_AVATAR_WINDOW", "100ms", "RATE_LIMIT_UPLOAD_AVATAR_WINDOW must be at least 1s"},
	} {
		t.Run(test.key, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv(test.key, test.value)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateAPIAuth() error = %v, want %q", err, test.want)
			}
		})
	}
}

// The endpoint is prefixed with https:// by the COS adapter, so a value that
// already carries a scheme would produce an unrecoverable URL at upload time.
func TestLoadRejectsSchemeInStorageEndpoint(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	setStorageEnv(t)
	t.Setenv("STORAGE_ENDPOINT", "https://sast-link-1250000000.cos.ap-nanjing.myqcloud.com")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err = cfg.ValidateAPIAuth(); err == nil || !strings.Contains(err.Error(), "bare host") {
		t.Fatalf("ValidateAPIAuth() error = %v, want endpoint scheme rejection", err)
	}
}
