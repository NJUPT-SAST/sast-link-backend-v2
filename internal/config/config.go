// Package config loads and validates application configuration from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all application configuration.
type Config struct {
	App        AppConfig        `mapstructure:"app"`
	DB         DBConfig         `mapstructure:"db"`
	Redis      RedisConfig      `mapstructure:"redis"`
	JWT        JWTConfig        `mapstructure:"jwt"`
	SMTP       SMTPConfig       `mapstructure:"smtp"`
	CORS       CORSConfig       `mapstructure:"cors"`
	OAuth      OAuthConfig      `mapstructure:"oauth"`
	Storage    StorageConfig    `mapstructure:"storage"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
}

// AppConfig holds application-level settings.
type AppConfig struct {
	Env      string `mapstructure:"env"`
	Port     int    `mapstructure:"port"`
	LogLevel string `mapstructure:"log_level"`
}

// DBConfig holds database connection settings.
type DBConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Database string `mapstructure:"database"`
	SSLMode  string `mapstructure:"ssl_mode"`
}

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// JWTConfig holds JWT signing settings.
// SecretKey / SecretKeyPrev are RSA private keys (PEM) for RS256,
// matching the env var names used in PRD §3.2 (JWT_SECRET_KEY / JWT_SECRET_KEY_PREV).
type JWTConfig struct {
	SecretKey          string `mapstructure:"secret_key"`
	SecretKeyPrev      string `mapstructure:"secret_key_prev"`
	AccessTokenExpiry  string `mapstructure:"access_token_expiry"`
	RefreshTokenExpiry string `mapstructure:"refresh_token_expiry"`
}

// SMTPConfig holds email server settings.
type SMTPConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	From     string `mapstructure:"from"`
	UseTLS   bool   `mapstructure:"use_tls"`
}

// CORSConfig holds CORS settings.
type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
}

// OAuthProviderConfig holds a single OAuth provider settings.
type OAuthProviderConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURI  string `mapstructure:"redirect_uri"`
}

// OAuthConfig holds all OAuth provider settings.
type OAuthConfig struct {
	Feishu OAuthProviderConfig `mapstructure:"feishu"`
	GitHub OAuthProviderConfig `mapstructure:"github"`
}

// StorageConfig holds object storage settings.
type StorageConfig struct {
	Provider  string `mapstructure:"provider"` // cos
	Endpoint  string `mapstructure:"endpoint"`
	Region    string `mapstructure:"region"`
	Bucket    string `mapstructure:"bucket"`
	AccessKey string `mapstructure:"access_key"`
	SecretKey string `mapstructure:"secret_key"`
	BaseURL   string `mapstructure:"base_url"` // public CDN base URL
}

// RateLimitConfig holds rate limiting settings.
type RateLimitConfig struct {
	GlobalRPS    int `mapstructure:"global_rps"`     // global requests per second per IP
	LoginRPM     int `mapstructure:"login_rpm"`      // login requests per minute per IP
	SendEmailRPM int `mapstructure:"send_email_rpm"` // send email requests per minute per account
	CaptchaRPM   int `mapstructure:"captcha_rpm"`    // captcha verify requests per minute per IP
	RegisterRPH  int `mapstructure:"register_rph"`   // register requests per hour per IP
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	v := viper.New()
	v.SetEnvPrefix("")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// App defaults
	v.SetDefault("app.env", getEnv("APP_ENV", "development"))
	v.SetDefault("app.port", getEnvInt("APP_PORT", 8080))
	v.SetDefault("app.log_level", getEnv("LOG_LEVEL", "info"))

	// DB defaults
	v.SetDefault("db.host", getEnv("DB_HOST", "localhost"))
	v.SetDefault("db.port", getEnvInt("DB_PORT", 5432))
	v.SetDefault("db.user", getEnv("DB_USER", "sastlink"))
	v.SetDefault("db.password", getEnv("DB_PASSWORD", ""))
	v.SetDefault("db.database", getEnv("DB_NAME", "sastlink"))
	v.SetDefault("db.ssl_mode", getEnv("DB_SSLMODE", "disable"))

	// Redis defaults
	v.SetDefault("redis.host", getEnv("REDIS_HOST", "localhost"))
	v.SetDefault("redis.port", getEnvInt("REDIS_PORT", 6379))
	v.SetDefault("redis.password", getEnv("REDIS_PASSWORD", ""))
	v.SetDefault("redis.db", getEnvInt("REDIS_DB", 0))

	// JWT defaults
	v.SetDefault("jwt.secret_key", getEnv("JWT_SECRET_KEY", ""))
	v.SetDefault("jwt.secret_key_prev", getEnv("JWT_SECRET_KEY_PREV", ""))
	v.SetDefault("jwt.access_token_expiry", getEnv("JWT_ACCESS_TOKEN_EXPIRY", "1h"))
	v.SetDefault("jwt.refresh_token_expiry", getEnv("JWT_REFRESH_TOKEN_EXPIRY", "720h"))

	// SMTP defaults
	v.SetDefault("smtp.host", getEnv("SMTP_HOST", ""))
	v.SetDefault("smtp.port", getEnvInt("SMTP_PORT", 587))
	v.SetDefault("smtp.username", getEnv("SMTP_USERNAME", ""))
	v.SetDefault("smtp.password", getEnv("SMTP_PASSWORD", ""))
	v.SetDefault("smtp.from", getEnv("SMTP_FROM", ""))
	v.SetDefault("smtp.use_tls", getEnvBool("SMTP_USE_TLS", true))

	// CORS defaults
	v.SetDefault("cors.allowed_origins", getEnvSlice("CORS_ALLOWED_ORIGINS", []string{"*"}))

	// OAuth defaults
	v.SetDefault("oauth.feishu.enabled", getEnvBool("OAUTH_FEISHU_ENABLED", false))
	v.SetDefault("oauth.feishu.client_id", getEnv("OAUTH_FEISHU_CLIENT_ID", ""))
	v.SetDefault("oauth.feishu.client_secret", getEnv("OAUTH_FEISHU_CLIENT_SECRET", ""))
	v.SetDefault("oauth.feishu.redirect_uri", getEnv("OAUTH_FEISHU_REDIRECT_URI", ""))
	v.SetDefault("oauth.github.enabled", getEnvBool("OAUTH_GITHUB_ENABLED", false))
	v.SetDefault("oauth.github.client_id", getEnv("OAUTH_GITHUB_CLIENT_ID", ""))
	v.SetDefault("oauth.github.client_secret", getEnv("OAUTH_GITHUB_CLIENT_SECRET", ""))
	v.SetDefault("oauth.github.redirect_uri", getEnv("OAUTH_GITHUB_REDIRECT_URI", ""))

	// Storage defaults
	v.SetDefault("storage.provider", getEnv("STORAGE_PROVIDER", "cos"))
	v.SetDefault("storage.endpoint", getEnv("STORAGE_ENDPOINT", ""))
	v.SetDefault("storage.region", getEnv("STORAGE_REGION", ""))
	v.SetDefault("storage.bucket", getEnv("STORAGE_BUCKET", ""))
	v.SetDefault("storage.access_key", getEnv("STORAGE_ACCESS_KEY", ""))
	v.SetDefault("storage.secret_key", getEnv("STORAGE_SECRET_KEY", ""))
	v.SetDefault("storage.base_url", getEnv("STORAGE_BASE_URL", ""))

	// Rate limit defaults
	v.SetDefault("rate_limit.global_rps", getEnvInt("RATE_LIMIT_GLOBAL_RPS", 100))
	v.SetDefault("rate_limit.login_rpm", getEnvInt("RATE_LIMIT_LOGIN_RPM", 5))
	v.SetDefault("rate_limit.send_email_rpm", getEnvInt("RATE_LIMIT_SEND_EMAIL_RPM", 3))
	v.SetDefault("rate_limit.captcha_rpm", getEnvInt("RATE_LIMIT_CAPTCHA_RPM", 5))
	v.SetDefault("rate_limit.register_rph", getEnvInt("RATE_LIMIT_REGISTER_RPH", 3))

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

// Validate checks required configuration values.
func (c *Config) Validate() error {
	if c.JWT.SecretKey == "" {
		return fmt.Errorf("JWT_SECRET_KEY is required")
	}
	if c.DB.Password == "" {
		return fmt.Errorf("DB_PASSWORD is required")
	}
	if c.Redis.Password == "" {
		return fmt.Errorf("REDIS_PASSWORD is required")
	}
	return nil
}

// DSN returns the PostgreSQL connection string.
func (c *DBConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode,
	)
}

// Addr returns the Redis server address.
func (c *RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
		slog.Warn("invalid integer env var, using fallback", "key", key, "value", v, "fallback", fallback)
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		return strings.EqualFold(v, "true") || v == "1"
	}
	return fallback
}

func getEnvSlice(key string, fallback []string) []string {
	if v := os.Getenv(key); v != "" {
		return strings.Split(v, ",")
	}
	return fallback
}
