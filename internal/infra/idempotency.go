package infra

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// IdempotencyStore 幂等性存储接口.
type IdempotencyStore interface {
	// Get 获取已缓存的响应，不存在返回 nil.
	Get(ctx context.Context, key string) (*IdempotencyRecord, error)
	// Set 缓存响应，TTL 默认 24 小时.
	Set(ctx context.Context, key string, record *IdempotencyRecord, ttl time.Duration) error
}

// IdempotencyRecord 缓存的响应记录.
type IdempotencyRecord struct {
	StatusCode int             `json:"status_code"`
	Body       json.RawMessage `json:"body"`
	CreatedAt  time.Time       `json:"created_at"`
}

const idempotencyKeyPrefix = "sastlink:idempotency"

// RedisIdempotencyStore Redis 实现的幂等性存储.
type RedisIdempotencyStore struct {
	rdb *redis.Client
}

// NewRedisIdempotencyStore 创建 Redis 幂等性存储.
func NewRedisIdempotencyStore(rdb *redis.Client) *RedisIdempotencyStore {
	return &RedisIdempotencyStore{rdb: rdb}
}

// Get 获取已缓存的响应.
func (s *RedisIdempotencyStore) Get(ctx context.Context, key string) (*IdempotencyRecord, error) {
	data, err := s.rdb.Get(ctx, fmt.Sprintf("%s:%s", idempotencyKeyPrefix, key)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record IdempotencyRecord
	if err := json.Unmarshal([]byte(data), &record); err != nil {
		return nil, fmt.Errorf("unmarshal idempotency record: %w", err)
	}
	return &record, nil
}

// Set 缓存响应.
func (s *RedisIdempotencyStore) Set(ctx context.Context, key string, record *IdempotencyRecord, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, fmt.Sprintf("%s:%s", idempotencyKeyPrefix, key), data, ttl).Err()
}
