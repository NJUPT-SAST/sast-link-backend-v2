package config

import (
	"os"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	// Unset all env vars to test defaults
	os.Clearenv()
	t.Setenv("JWT_SECRET_KEY", "test-secret-key-at-least-32-bytes-long")
	t.Setenv("DB_PASSWORD", "test-db-password")
	t.Setenv("REDIS_PASSWORD", "test-redis-password")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.App.Env != "development" {
		t.Errorf("App.Env = %q, want development", cfg.App.Env)
	}
	if cfg.App.Port != 8080 {
		t.Errorf("App.Port = %d, want 8080", cfg.App.Port)
	}
	if cfg.App.LogLevel != "info" {
		t.Errorf("App.LogLevel = %q, want info", cfg.App.LogLevel)
	}
	if cfg.DB.Host != "localhost" {
		t.Errorf("DB.Host = %q, want localhost", cfg.DB.Host)
	}
	if cfg.Redis.Host != "localhost" {
		t.Errorf("Redis.Host = %q, want localhost", cfg.Redis.Host)
	}
	if cfg.JWT.Expiry != "168h" {
		t.Errorf("JWT.Expiry = %q, want 168h", cfg.JWT.Expiry)
	}
}

func TestLoad_CustomValues(t *testing.T) {
	os.Clearenv()
	t.Setenv("JWT_SECRET_KEY", "test-secret-key-at-least-32-bytes-long")
	t.Setenv("DB_PASSWORD", "test-db-password")
	t.Setenv("REDIS_PASSWORD", "test-redis-password")
	t.Setenv("APP_ENV", "production")
	t.Setenv("APP_PORT", "9090")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("DB_HOST", "db.example.com")
	t.Setenv("REDIS_HOST", "redis.example.com")
	t.Setenv("JWT_EXPIRY", "24h")
	t.Setenv("JWT_SECRET_KEY_PREV", "previous-secret-key-at-least-32-bytes")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.App.Env != "production" {
		t.Errorf("App.Env = %q, want production", cfg.App.Env)
	}
	if cfg.App.Port != 9090 {
		t.Errorf("App.Port = %d, want 9090", cfg.App.Port)
	}
	if cfg.App.LogLevel != "debug" {
		t.Errorf("App.LogLevel = %q, want debug", cfg.App.LogLevel)
	}
	if cfg.DB.Host != "db.example.com" {
		t.Errorf("DB.Host = %q, want db.example.com", cfg.DB.Host)
	}
	if cfg.Redis.Host != "redis.example.com" {
		t.Errorf("Redis.Host = %q, want redis.example.com", cfg.Redis.Host)
	}
	if cfg.JWT.Expiry != "24h" {
		t.Errorf("JWT.Expiry = %q, want 24h", cfg.JWT.Expiry)
	}
	if cfg.JWT.SecretKeyPrev != "previous-secret-key-at-least-32-bytes" {
		t.Errorf("JWT.SecretKeyPrev = %q, want previous-secret-key...", cfg.JWT.SecretKeyPrev)
	}
}

func TestLoad_MissingJWTSecret(t *testing.T) {
	os.Clearenv()
	t.Setenv("DB_PASSWORD", "test")
	t.Setenv("REDIS_PASSWORD", "test")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() expected error for missing JWT_SECRET_KEY")
	}
}

func TestLoad_MissingDBPassword(t *testing.T) {
	os.Clearenv()
	t.Setenv("JWT_SECRET_KEY", "test-secret-key-at-least-32-bytes-long")
	t.Setenv("REDIS_PASSWORD", "test")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() expected error for missing DB_PASSWORD")
	}
}

func TestLoad_MissingRedisPassword(t *testing.T) {
	os.Clearenv()
	t.Setenv("JWT_SECRET_KEY", "test-secret-key-at-least-32-bytes-long")
	t.Setenv("DB_PASSWORD", "test")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() expected error for missing REDIS_PASSWORD")
	}
}

func TestDBConfig_DSN(t *testing.T) {
	cfg := DBConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "sastlink",
		Password: "secret",
		Database: "sastlink",
		SSLMode:  "disable",
	}
	want := "host=localhost port=5432 user=sastlink password=secret dbname=sastlink sslmode=disable"
	if got := cfg.DSN(); got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}

func TestRedisConfig_Addr(t *testing.T) {
	cfg := RedisConfig{Host: "localhost", Port: 6379}
	if got := cfg.Addr(); got != "localhost:6379" {
		t.Errorf("Addr() = %q, want localhost:6379", got)
	}
}

func TestGetEnv(t *testing.T) {
	t.Setenv("TEST_KEY", "value")
	if got := getEnv("TEST_KEY", "fallback"); got != "value" {
		t.Errorf("getEnv = %q, want value", got)
	}
	if got := getEnv("TEST_KEY_MISSING", "fallback"); got != "fallback" {
		t.Errorf("getEnv = %q, want fallback", got)
	}
}

func TestGetEnvInt(t *testing.T) {
	t.Setenv("TEST_INT", "42")
	if got := getEnvInt("TEST_INT", 0); got != 42 {
		t.Errorf("getEnvInt = %d, want 42", got)
	}
	if got := getEnvInt("TEST_INT_MISSING", 10); got != 10 {
		t.Errorf("getEnvInt = %d, want 10", got)
	}
	t.Setenv("TEST_INT_BAD", "not-a-number")
	if got := getEnvInt("TEST_INT_BAD", 20); got != 20 {
		t.Errorf("getEnvInt = %d, want 20", got)
	}
}

func TestGetEnvBool(t *testing.T) {
	t.Setenv("TEST_BOOL_TRUE", "true")
	t.Setenv("TEST_BOOL_ONE", "1")
	t.Setenv("TEST_BOOL_FALSE", "false")

	if !getEnvBool("TEST_BOOL_TRUE", false) {
		t.Error("getEnvBool(true) = false, want true")
	}
	if !getEnvBool("TEST_BOOL_ONE", false) {
		t.Error("getEnvBool(1) = false, want true")
	}
	if getEnvBool("TEST_BOOL_FALSE", true) {
		t.Error("getEnvBool(false) = true, want false")
	}
	if !getEnvBool("TEST_BOOL_MISSING", true) {
		t.Error("getEnvBool(missing, true) = false, want true")
	}
}

func TestGetEnvSlice(t *testing.T) {
	t.Setenv("TEST_SLICE", "a,b,c")
	got := getEnvSlice("TEST_SLICE", nil)
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("getEnvSlice = %v, want [a b c]", got)
	}
	got2 := getEnvSlice("TEST_SLICE_MISSING", []string{"x"})
	if len(got2) != 1 || got2[0] != "x" {
		t.Errorf("getEnvSlice = %v, want [x]", got2)
	}
}
