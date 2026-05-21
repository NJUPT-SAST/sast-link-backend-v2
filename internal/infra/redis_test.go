package infra

import (
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
)

func TestNewRedis_InvalidAddr(t *testing.T) {
	cfg := config.RedisConfig{
		Host:     "invalid-host",
		Port:     6379,
		Password: "",
		DB:       0,
	}
	// Connection should fail with invalid host
	_, err := NewRedis(&cfg)
	if err == nil {
		t.Fatal("redis connection succeeded unexpectedly; may have local redis")
	}
}

func TestNewRedis_AddrFormat(t *testing.T) {
	cfg := config.RedisConfig{Host: "localhost", Port: 6379}
	if got := cfg.Addr(); got != "localhost:6379" {
		t.Errorf("Addr = %q, want localhost:6379", got)
	}
}
