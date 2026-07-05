package config

import (
	"strings"
	"testing"
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
}
