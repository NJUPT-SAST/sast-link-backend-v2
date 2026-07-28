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
