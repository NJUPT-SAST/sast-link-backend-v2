// Package config loads application configuration from environment variables.
package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
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
	case c.JWTAccessTokenExpiry <= 0:
		return fmt.Errorf("JWT_ACCESS_TOKEN_EXPIRY must be positive")
	case c.JWTRefreshTokenExpiry <= 0:
		return fmt.Errorf("JWT_REFRESH_TOKEN_EXPIRY must be positive")
	case (c.JWTSecretKeyPrev == "") != (c.JWTPreviousKID == ""):
		return fmt.Errorf("JWT_SECRET_KEY_PREV and JWT_PREVIOUS_KID must be both set or both empty")
	}
	return nil
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
