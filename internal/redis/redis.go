// Package redis provides a go-redis client.
package redis

import (
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// New returns a go-redis client configured with the provided address, password,
// and database index. The client is tuned for a 1-core deployment: no retries (a
// fail-open Redis dependency must not turn a transient blip into a 10ms+ tail
// that has no effect on the outcome), a small idle pool to keep connections hot
// across bursts, and explicit short timeouts so a wedged Redis fails the request
// fast instead of hanging it.
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
