package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all application configuration.
type Config struct {
	App   AppConfig   `mapstructure:"app"`
	DB    DBConfig    `mapstructure:"db"`
	Redis RedisConfig `mapstructure:"redis"`
	JWT   JWTConfig   `mapstructure:"jwt"`
	SMTP  SMTPConfig  `mapstructure:"smtp"`
	CORS  CORSConfig  `mapstructure:"cors"`
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
type JWTConfig struct {
	SecretKey string `mapstructure:"secret_key"`
	Expiry    string `mapstructure:"expiry"`
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
	v.SetDefault("jwt.expiry", getEnv("JWT_EXPIRY", "168h"))

	// SMTP defaults
	v.SetDefault("smtp.host", getEnv("SMTP_HOST", ""))
	v.SetDefault("smtp.port", getEnvInt("SMTP_PORT", 587))
	v.SetDefault("smtp.username", getEnv("SMTP_USERNAME", ""))
	v.SetDefault("smtp.password", getEnv("SMTP_PASSWORD", ""))
	v.SetDefault("smtp.from", getEnv("SMTP_FROM", ""))
	v.SetDefault("smtp.use_tls", getEnvBool("SMTP_USE_TLS", true))

	// CORS defaults
	v.SetDefault("cors.allowed_origins", getEnvSlice("CORS_ALLOWED_ORIGINS", []string{"*"}))

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
