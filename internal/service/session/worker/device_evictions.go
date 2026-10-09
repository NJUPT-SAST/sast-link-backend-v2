package sessionworker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
)

type DeviceEvictionStore interface {
	PendingDeviceEvictions(context.Context, int, int) ([]internalredis.DeviceEviction, error)
	AckDeviceEviction(context.Context, string) error
}
type DeviceEvictionResolver interface {
	ResolveDeviceEviction(context.Context, int64, string, string, string, time.Time, time.Time) (bool, error)
}
type DeviceEvictions struct {
	Store  DeviceEvictionStore
	Tokens DeviceEvictionResolver
}

func (w DeviceEvictions) Run(ctx context.Context) error {
	if w.Store == nil || w.Tokens == nil {
		return fmt.Errorf("device eviction worker requires journal and token resolver")
	}
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	offset := 0
	for {
		offset = w.process(ctx, offset)
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
	}
}

func (w DeviceEvictions) process(ctx context.Context, offset int) int {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	items, err := w.Store.PendingDeviceEvictions(ctx, offset, 100)
	if err != nil {
		if ctx.Err() == nil {
			slog.WarnContext(ctx, "list device eviction journal", "error", err)
		}
		return offset
	}
	for _, item := range items {
		resolved, err := w.Tokens.ResolveDeviceEviction(ctx, item.UserID, item.TokenHash, item.SourceFamily, item.Evicted, time.Unix(item.ExpiresAt, 0), time.Now().UTC())
		if err != nil {
			slog.WarnContext(ctx, "resolve device eviction", "error", err)
			continue
		}
		if !resolved {
			continue
		}
		if err := w.Store.AckDeviceEviction(ctx, item.Receipt); err != nil {
			slog.WarnContext(ctx, "ack device eviction", "error", err)
		}
	}
	if len(items) < 100 {
		return 0
	}
	return offset + 100
}
