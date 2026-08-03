package redis

import (
	"context"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
)

func TestDeviceKeys(t *testing.T) {
	keys := NewKeys("sast-link:test")
	if got, want := keys.Devices(42), "sast-link:test:devices:42"; got != want {
		t.Fatalf("Devices key = %q, want %q", got, want)
	}
	if got, want := keys.Device("family-1"), "sast-link:test:device:family-1"; got != want {
		t.Fatalf("Device key = %q, want %q", got, want)
	}
	if devices, device := keys.Devices(1), keys.Device("1"); devices == device {
		t.Fatalf("Devices and Device keys collided: %q", devices)
	}
}

func TestRegisterAndListDevices(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	if err := store.RegisterDevice(ctx, 42, "family-1", "browser/5", "10.0.0.1", now, time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	later := now.Add(time.Minute)
	if err := store.RegisterDevice(ctx, 42, "family-2", "app/2", "10.0.0.2", later, time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}

	devices, err := store.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("devices = %#v, want 2", devices)
	}
	// Newest login first.
	if devices[0].DeviceID != "family-2" || devices[1].DeviceID != "family-1" {
		t.Fatalf("device order = %#v, want newest first", devices)
	}
	if devices[0].UA != "app/2" || devices[0].IP != "10.0.0.2" {
		t.Fatalf("device meta = %+v", devices[0])
	}
	if !devices[0].LoginTime.Equal(later) || !devices[0].LastSeen.Equal(later) {
		t.Fatalf("device times = login %v last_seen %v, want %v", devices[0].LoginTime, devices[0].LastSeen, later)
	}
	if !devices[1].LoginTime.Equal(now) {
		t.Fatalf("second device login time = %v, want %v", devices[1].LoginTime, now)
	}
}

func TestRegisterDeviceSetsTTL(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	if err := store.RegisterDevice(ctx, 42, "family-1", "ua", "ip", now, 90*time.Second, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	for _, key := range []string{store.Keys.Devices(42), store.Keys.Device("family-1")} {
		ttl, err := client.TTL(ctx, key).Result()
		if err != nil {
			t.Fatalf("TTL(%q) returned error: %v", key, err)
		}
		if ttl <= 0 || ttl > 90*time.Second {
			t.Fatalf("TTL(%q) = %v, want about 90s", key, ttl)
		}
	}
}

func TestRegisterDeviceEvictsOldestBeyondLimit(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	base := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	for i, id := range []string{"family-1", "family-2", "family-3"} {
		if err := store.RegisterDevice(ctx, 42, id, "ua", "ip", base.Add(time.Duration(i)*time.Minute), time.Hour, 2); err != nil {
			t.Fatalf("RegisterDevice %s returned error: %v", id, err)
		}
	}

	devices, err := store.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("devices = %#v, want the cap of 2", devices)
	}
	if devices[0].DeviceID != "family-3" || devices[1].DeviceID != "family-2" {
		t.Fatalf("devices = %#v, want family-3 and family-2 (oldest evicted)", devices)
	}
	// The evicted device's Hash must be gone, not just its set membership.
	if exists, err := client.Exists(ctx, store.Keys.Device("family-1")).Result(); err != nil || exists != 0 {
		t.Fatalf("evicted device hash exists = %v (err %v), want 0", exists, err)
	}
}

func TestTouchDeviceUpdatesLastSeenWithoutExtendingTTL(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	if err := store.RegisterDevice(ctx, 42, "family-1", "ua", "ip", now, time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	before, err := client.TTL(ctx, store.Keys.Device("family-1")).Result()
	if err != nil {
		t.Fatalf("TTL returned error: %v", err)
	}
	later := now.Add(30 * time.Minute)
	if err := store.TouchDevice(ctx, 42, "family-1", later); err != nil {
		t.Fatalf("TouchDevice returned error: %v", err)
	}

	devices, err := store.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(devices) != 1 || !devices[0].LastSeen.Equal(later) {
		t.Fatalf("devices = %#v, want last_seen updated to %v", devices, later)
	}
	if !devices[0].LoginTime.Equal(now) {
		t.Fatalf("login_time changed to %v, want %v", devices[0].LoginTime, now)
	}
	after, err := client.TTL(ctx, store.Keys.Device("family-1")).Result()
	if err != nil {
		t.Fatalf("TTL returned error: %v", err)
	}
	// TTL must not have been extended: an abandoned device ages out even while
	// its refresh loop keeps it alive in the token table.
	if after > before+time.Second {
		t.Fatalf("TTL extended from %v to %v by touch", before, after)
	}
}

// A device evicted by the per-user cap must not be resurrected by its still
// valid refresh token: TouchDevice only counts while the device is a member of
// the set, so an evicted device's refresh cannot recreate a TTL-less Hash.
func TestTouchDeviceDoesNotRecreateEvictedRecord(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	// Cap of 1: registering a second device evicts the first.
	if err := store.RegisterDevice(ctx, 42, "family-1", "ua", "ip", now, time.Hour, 1); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	if err := store.RegisterDevice(ctx, 42, "family-2", "ua", "ip", now.Add(time.Minute), time.Hour, 1); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	// The evicted device's session is still valid and refreshes; the touch must
	// not recreate its record.
	if err := store.TouchDevice(ctx, 42, "family-1", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("TouchDevice returned error: %v", err)
	}
	if exists, err := client.Exists(ctx, store.Keys.Device("family-1")).Result(); err != nil || exists != 0 {
		t.Fatalf("evicted device hash exists = %v (err %v), want 0 after touch", exists, err)
	}
	devices, err := store.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(devices) != 1 || devices[0].DeviceID != "family-2" {
		t.Fatalf("devices = %#v, want only family-2", devices)
	}
}

func TestRemoveDevice(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	if err := store.RegisterDevice(ctx, 42, "family-1", "ua", "ip", now, time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	if err := store.RegisterDevice(ctx, 42, "family-2", "ua", "ip", now.Add(time.Minute), time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	if err := store.RemoveDevice(ctx, 42, "family-1"); err != nil {
		t.Fatalf("RemoveDevice returned error: %v", err)
	}

	devices, err := store.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(devices) != 1 || devices[0].DeviceID != "family-2" {
		t.Fatalf("devices = %#v, want only family-2 left", devices)
	}
	if exists, err := client.Exists(ctx, store.Keys.Device("family-1")).Result(); err != nil || exists != 0 {
		t.Fatalf("removed device hash exists = %v (err %v), want 0", exists, err)
	}
}

func TestRemoveAllDevices(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	for i, id := range []string{"family-1", "family-2"} {
		if err := store.RegisterDevice(ctx, 42, id, "ua", "ip", now.Add(time.Duration(i)*time.Minute), time.Hour, 5); err != nil {
			t.Fatalf("RegisterDevice %s returned error: %v", id, err)
		}
	}
	// Another user's devices must survive a per-user clear.
	if err := store.RegisterDevice(ctx, 7, "family-7", "ua", "ip", now, time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	if err := store.RemoveAllDevices(ctx, 42); err != nil {
		t.Fatalf("RemoveAllDevices returned error: %v", err)
	}

	devices, err := store.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(devices) != 0 {
		t.Fatalf("devices = %#v, want none left", devices)
	}
	others, err := store.ListDevices(ctx, 7)
	if err != nil {
		t.Fatalf("ListDevices(user 7) returned error: %v", err)
	}
	if len(others) != 1 || others[0].DeviceID != "family-7" {
		t.Fatalf("other user's devices = %#v, want family-7 untouched", others)
	}
}

func TestDeviceOwnedBy(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	if err := store.RegisterDevice(ctx, 42, "family-1", "ua", "ip", now, time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}

	owned, err := store.DeviceOwnedBy(ctx, 42, "family-1")
	if err != nil {
		t.Fatalf("DeviceOwnedBy returned error: %v", err)
	}
	if !owned {
		t.Fatal("DeviceOwnedBy = false, want true for an owned device")
	}

	// A device of another user, a foreign string, and an unknown user must all
	// answer false without error.
	for _, probe := range []struct {
		userID   int64
		deviceID string
	}{
		{7, "family-1"},
		{42, "family-other"},
		{999, "family-1"},
	} {
		owned, err := store.DeviceOwnedBy(ctx, probe.userID, probe.deviceID)
		if err != nil {
			t.Fatalf("DeviceOwnedBy(%d, %q) returned error: %v", probe.userID, probe.deviceID, err)
		}
		if owned {
			t.Fatalf("DeviceOwnedBy(%d, %q) = true, want false", probe.userID, probe.deviceID)
		}
	}
}

func TestListDevicesOnMissingSetIsEmpty(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}

	devices, err := store.ListDevices(ctx, 999)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(devices) != 0 {
		t.Fatalf("devices = %#v, want empty list for a user without devices", devices)
	}
}
