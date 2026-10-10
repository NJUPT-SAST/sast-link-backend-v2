// Package redis provides a go-redis client.
package redis

import (
	"context"
	"crypto/sha1" // #nosec G505 -- SHA-1 is Redis EVALSHA script-cache keying, not a security use
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/metrics"
)

// New returns a go-redis client configured with the provided address, password,
// and database index, tuned for a 1-core deployment with no retries, a small
// idle pool, and short timeouts.
func New(addr, password string, db int) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:                  addr,
		Password:              password,
		DB:                    db,
		MaxRetries:            -1, // Zero enables go-redis defaults; writes are not all replay-safe.
		ContextTimeoutEnabled: true,
		MinIdleConns:          4,
		MaxIdleConns:          8,
		DialTimeout:           3 * time.Second,
		ReadTimeout:           2 * time.Second,
		WriteTimeout:          2 * time.Second,
		PoolTimeout:           2 * time.Second,
	})
	client.AddHook(commandMetricsHook{})
	return client, nil
}

// commandMetricsHook records per-command latency on the metrics registry. The
// command label is normalized through metrics.NormalizeRedisCommand so a key or
// argument can never reach a label; pipelines land in their own bucket because
// one pipeline call covers many commands and would otherwise overcount neither
// accurately.
type commandMetricsHook struct{}

func (commandMetricsHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (commandMetricsHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		start := time.Now()
		err := next(ctx, cmd)
		metrics.RedisCommand(metrics.NormalizeRedisCommand(cmd.FullName()), time.Since(start))
		return err
	}
}

func (commandMetricsHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		start := time.Now()
		err := next(ctx, cmds)
		metrics.RedisCommand("pipeline", time.Since(start))
		return err
	}
}

// Close closes the redis client.
func Close(client *redis.Client) error {
	if err := client.Close(); err != nil {
		return fmt.Errorf("close redis: %w", err)
	}
	return nil
}

// evalScript runs a Lua script through EVALSHA and uploads it with EVAL only
// when the server answers NOSCRIPT (script cache flushed, restart, or first
// use). The package's scripts ride the hot paths — the limiter on every
// request they guard, the device touch on every refresh, one of them ~2KB —
// and re-uploading the source on every call spent bandwidth and a re-parse
// per invocation for a digest Redis already remembers. A concurrent burst of
// NOSCRIPTs each uploads once, which is exactly today's behavior; no worse,
// and self-correcting after the first EVAL lands.
func evalScript(ctx context.Context, client Cmdable, script string, keys []string, args ...any) *redis.Cmd {
	digest := scriptDigest(script)
	cmd := client.EvalSha(ctx, digest, keys, args...)
	if err := cmd.Err(); err != nil && strings.Contains(err.Error(), "NOSCRIPT") {
		return client.Eval(ctx, script, keys, args...)
	}
	return cmd
}

// scriptDigest returns the SHA-1 hex digest Redis keys its script cache by.
func scriptDigest(script string) string {
	sum := sha1.Sum([]byte(script)) // #nosec G401 -- SHA-1 is Redis's script-cache key convention (EVALSHA), not a security primitive here
	return hex.EncodeToString(sum[:])
}
