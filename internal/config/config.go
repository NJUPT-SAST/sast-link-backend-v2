// Package config loads application configuration from environment variables.
package config

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

const (
	minimumRefreshHMACSecretLen = 32
	// minimumHSTSMaxAge is one year in seconds, matching the PRD §7.2 default.
	// Smaller values leave the header present but effectively unenforced.
	minimumHSTSMaxAge = 31536000
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

	InternalOAuthClientID string        `env:"INTERNAL_OAUTH_CLIENT_ID" envDefault:"sast-link-web"`
	CORSAllowedOrigins    []string      `env:"CORS_ALLOWED_ORIGINS" envSeparator:","`
	TrustedProxies        []string      `env:"TRUSTED_PROXIES" envSeparator:"," envDefault:"127.0.0.1,::1"`
	HSTSMaxAge            int           `env:"HSTS_MAX_AGE" envDefault:"31536000"`
	RateLimitLoginRPM     int           `env:"RATE_LIMIT_LOGIN_RPM" envDefault:"5"`
	RateLimitLoginWindow  time.Duration `env:"RATE_LIMIT_LOGIN_WINDOW" envDefault:"15m"`
	LoginFailureLimit     int           `env:"LOGIN_FAILURE_LIMIT" envDefault:"10"`
	LoginFailureWindow    time.Duration `env:"LOGIN_FAILURE_WINDOW" envDefault:"15m"`
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

// ValidateAPIAuth validates auth settings required by cmd/api endpoints.
func (c *Config) ValidateAPIAuth() error {
	switch {
	case strings.TrimSpace(c.JWTSecretKey) == "":
		return fmt.Errorf("JWT_SECRET_KEY is required")
	case strings.TrimSpace(c.JWTActiveKID) == "":
		return fmt.Errorf("JWT_ACTIVE_KID is required")
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
	case c.LoginFailureLimit <= 0:
		return fmt.Errorf("LOGIN_FAILURE_LIMIT must be positive")
	case c.LoginFailureWindow <= 0:
		return fmt.Errorf("LOGIN_FAILURE_WINDOW must be positive")
	}
	normalizedProxies, err := normalizeTrustedProxies(c.TrustedProxies)
	if err != nil {
		return err
	}
	c.TrustedProxies = normalizedProxies
	return nil
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
