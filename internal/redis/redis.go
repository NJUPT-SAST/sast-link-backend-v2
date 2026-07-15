// Package redis provides a go-redis client.
package redis

import (
	"fmt"

	"github.com/redis/go-redis/v9"
)

// New returns a go-redis client configured with the provided address,
// password, and database index.
func New(addr, password string, db int) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
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
