package config

import (
	"strings"
	"testing"
	"time"
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
	t.Setenv("REFRESH_TOKEN_HMAC_SECRET", "refresh-hmac-secret")
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
	if cfg.RefreshTokenHMACSecret != "refresh-hmac-secret" {
		t.Errorf("RefreshTokenHMACSecret = %q, want refresh-hmac-secret", cfg.RefreshTokenHMACSecret)
	}
}

func TestLoadAllowsHealthOnlyWithoutCryptoMaterial(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("JWT_SECRET_KEY", "")
	t.Setenv("JWT_ACTIVE_KID", "")
	t.Setenv("REFRESH_TOKEN_HMAC_SECRET", "")

	if _, err := Load(); err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
}

func TestLoadRejectsNonPositiveAccessTokenExpiry(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("JWT_ACCESS_TOKEN_EXPIRY", "0")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "JWT_ACCESS_TOKEN_EXPIRY must be positive") {
		t.Fatalf("Load() error = %v, want JWT_ACCESS_TOKEN_EXPIRY positive validation", err)
	}
}

func TestLoadRejectsNonPositiveRefreshTokenExpiry(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("JWT_REFRESH_TOKEN_EXPIRY", "-1h")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "JWT_REFRESH_TOKEN_EXPIRY must be positive") {
		t.Fatalf("Load() error = %v, want JWT_REFRESH_TOKEN_EXPIRY positive validation", err)
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

func TestLoadRejectsPreviousKIDWithoutPreviousKey(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	t.Setenv("JWT_SECRET_KEY_PREV", "")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "JWT_SECRET_KEY_PREV and JWT_PREVIOUS_KID must be both set or both empty") {
		t.Fatalf("Load() error = %v, want previous key/kid pair validation", err)
	}
}
