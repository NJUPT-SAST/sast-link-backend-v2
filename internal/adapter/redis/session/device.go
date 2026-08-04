package sessionredis

import (
	"context"
	"time"

	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
)

// deviceTTL bounds every device record (PRD §6.1: 30d). Refreshes update
// last_seen without extending it, so an abandoned device ages out on its own.
const deviceTTL = 30 * 24 * time.Hour

// maxDevicesPerUser caps concurrent logged-in devices per user (PRD §6.1: 最多
// 5 台同时登录). The oldest login is evicted beyond the cap.
const maxDevicesPerUser = 5

// DeviceStore adapts the Redis device primitives to the session service port.
// The device ID is the token family ID, so a device dies exactly when its
// session dies.
type DeviceStore struct {
	Store internalredis.Store
}

func (d DeviceStore) RegisterDevice(ctx context.Context, userID int64, deviceID, ua, ip string, now time.Time) (string, error) {
	return d.Store.RegisterDevice(ctx, userID, deviceID, ua, ip, now, deviceTTL, maxDevicesPerUser)
}

func (d DeviceStore) TouchDevice(ctx context.Context, userID int64, deviceID, ua, ip string, now time.Time) (string, error) {
	return d.Store.TouchDevice(ctx, userID, deviceID, ua, ip, now, deviceTTL, maxDevicesPerUser)
}

func (d DeviceStore) RemoveDevice(ctx context.Context, userID int64, deviceID string) error {
	return d.Store.RemoveDevice(ctx, userID, deviceID)
}

func (d DeviceStore) RemoveAllDevices(ctx context.Context, userID int64) error {
	return d.Store.RemoveAllDevices(ctx, userID)
}

func (d DeviceStore) ListDevices(ctx context.Context, userID int64) ([]session.DeviceRecord, error) {
	infos, err := d.Store.ListDevices(ctx, userID)
	if err != nil {
		return nil, err
	}
	records := make([]session.DeviceRecord, 0, len(infos))
	for _, info := range infos {
		records = append(records, session.DeviceRecord{
			DeviceID:  info.DeviceID,
			UA:        info.UA,
			IP:        info.IP,
			LoginTime: info.LoginTime,
			LastSeen:  info.LastSeen,
		})
	}
	return records, nil
}

func (d DeviceStore) DeviceOwnedBy(ctx context.Context, userID int64, deviceID string) (bool, error) {
	return d.Store.DeviceOwnedBy(ctx, userID, deviceID)
}
