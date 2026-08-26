// Package redis provides a go-redis client.
package redis

import (
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// New returns a go-redis client configured with the provided address, password,
// and database index, tuned for a 1-core deployment with no retries, a small
// idle pool, and short timeouts.
func New(addr, password string, db int) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           db,
		MaxRetries:   0,
		MinIdleConns: 4,
		MaxIdleConns: 8,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		PoolTimeout:  2 * time.Second,
	})
	return client, nil
}

// Close closes the redis client.
func Close(client *redis.Client) error {
	if err := client.Close(); err != nil {
		return fmt.Errorf("close redis: %w", err)
	}
	return nil
}
