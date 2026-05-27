package service

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	captchaKeyPrefix = "sastlink:captcha:"
	captchaTTL       = 5 * time.Minute
	captchaCodeLen   = 5
)

// CaptchaService generates and verifies email verification codes.
type CaptchaService struct {
	rdb *redis.Client
}

func NewCaptchaService(rdb *redis.Client) *CaptchaService {
	return &CaptchaService{rdb: rdb}
}

// Generate creates a random code, stores it in Redis, and returns it.
func (s *CaptchaService) Generate(ctx context.Context, email string) (string, error) {
	code, err := generateCode()
	if err != nil {
		return "", fmt.Errorf("captcha generate: %w", err)
	}

	key := captchaKeyPrefix + email
	if err := s.rdb.Set(ctx, key, code, captchaTTL).Err(); err != nil {
		return "", fmt.Errorf("captcha store: %w", err)
	}

	return code, nil
}

// Verify checks the code for the given email. Returns true only on match.
// The code is deleted after a successful verification.
func (s *CaptchaService) Verify(ctx context.Context, email, code string) (bool, error) {
	key := captchaKeyPrefix + email

	stored, err := s.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("captcha verify: %w", err)
	}

	if !strings.EqualFold(stored, code) {
		return false, nil
	}

	s.rdb.Del(ctx, key)
	return true, nil
}

func generateCode() (string, error) {
	buf := make([]byte, 3)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
	return "S-" + raw[:captchaCodeLen], nil
}
