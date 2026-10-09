package redis

import (
	"context"
	"encoding/json"
	"fmt"
)

type DeviceEviction struct {
	OperationID  string `json:"operation_id"`
	TokenHash    string `json:"token_hash"`
	UserID       int64  `json:"user_id"`
	ExpiresAt    int64  `json:"expires_at"`
	SourceFamily string `json:"source_family"`
	Evicted      string `json:"evicted"`
	Receipt      string `json:"-"`
}

func (s Store) PendingDeviceEvictions(ctx context.Context, offset, limit int) ([]DeviceEviction, error) {
	// Destructive popping would lose work when the DB is down. Entries stay until
	// the family revoke/outbox transaction commits and the receipt is acked.
	values, err := evalScript(ctx, s.Client, `return redis.call("ZRANGE", KEYS[1], tonumber(ARGV[1]), tonumber(ARGV[1])+tonumber(ARGV[2])-1)`, []string{s.Keys.join("{dev}", "pending_evictions")}, offset, limit).StringSlice()
	if err != nil {
		return nil, err
	}
	out := make([]DeviceEviction, 0, len(values))
	for _, value := range values {
		var item DeviceEviction
		if err := json.Unmarshal([]byte(value), &item); err != nil {
			return nil, fmt.Errorf("decode device eviction: %w", err)
		}
		item.Receipt = value
		out = append(out, item)
	}
	return out, nil
}
func (s Store) AckDeviceEviction(ctx context.Context, receipt string) error {
	return evalScript(ctx, s.Client, `return redis.call("ZREM", KEYS[1], ARGV[1])`, []string{s.Keys.join("{dev}", "pending_evictions")}, receipt).Err()
}
