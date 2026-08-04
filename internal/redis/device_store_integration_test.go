package redis

import (
	"context"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

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

	if _, err := store.RegisterDevice(ctx, 42, "family-1", "browser/5", "10.0.0.1", now, time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	later := now.Add(time.Minute)
	if _, err := store.RegisterDevice(ctx, 42, "family-2", "app/2", "10.0.0.2", later, time.Hour, 5); err != nil {
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

	if _, err := store.RegisterDevice(ctx, 42, "family-1", "ua", "ip", now, 90*time.Second, 5); err != nil {
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

	// Cap of 2: registering a third device evicts the oldest.
	for i, id := range []string{"family-1", "family-2", "family-3"} {
		evicted, err := store.RegisterDevice(ctx, 42, id, "ua", "ip", base.Add(time.Duration(i)*time.Minute), time.Hour, 2)
		if err != nil {
			t.Fatalf("RegisterDevice %s returned error: %v", id, err)
		}
		if i < 2 && evicted != "" {
			t.Fatalf("RegisterDevice %s evicted %q, want none before the cap", id, evicted)
		}
		if i == 2 && evicted != "family-1" {
			t.Fatalf("RegisterDevice %s evicted %q, want family-1 (the oldest)", id, evicted)
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

	if _, err := store.RegisterDevice(ctx, 42, "family-1", "ua", "ip", now, time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	before, err := client.TTL(ctx, store.Keys.Device("family-1")).Result()
	if err != nil {
		t.Fatalf("TTL returned error: %v", err)
	}
	later := now.Add(30 * time.Minute)
	if _, touchErr := store.TouchDevice(ctx, 42, "family-1", "ua", "ip", later, time.Hour, 5); touchErr != nil {
		t.Fatalf("TouchDevice returned error: %v", touchErr)
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

// The live branch must not rebuild a TTL-less Hash: if the Hash lost its TTL
// (expiry skew between the two keys, an eviction-policy drop, an external
// delete) while the set member is still alive, the HSET would resurrect it as
// a never-expiring orphan. The touch re-applies the TTL only when it is
// missing, and only for the affected key — an intact record's TTL is still
// never extended.
func TestTouchDeviceReappliesTTLWhenMissing(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	if _, err := store.RegisterDevice(ctx, 42, "family-1", "ua", "ip", now, time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	// Strip the TTL from both keys: the member is alive but the record and the
	// set are now immortal — exactly the state a refresh must not preserve.
	if err := client.Persist(ctx, store.Keys.Device("family-1")).Err(); err != nil {
		t.Fatalf("Persist hash: %v", err)
	}
	if err := client.Persist(ctx, store.Keys.Devices(42)).Err(); err != nil {
		t.Fatalf("Persist set: %v", err)
	}

	later := now.Add(30 * time.Minute)
	if _, touchErr := store.TouchDevice(ctx, 42, "family-1", "ua", "ip", later, time.Hour, 5); touchErr != nil {
		t.Fatalf("TouchDevice returned error: %v", touchErr)
	}

	hashTTL, err := client.TTL(ctx, store.Keys.Device("family-1")).Result()
	if err != nil {
		t.Fatalf("TTL returned error: %v", err)
	}
	if hashTTL <= 0 || hashTTL > time.Hour {
		t.Fatalf("hash TTL = %v after touch, want a fresh ~1h instead of none", hashTTL)
	}
	setTTL, err := client.TTL(ctx, store.Keys.Devices(42)).Result()
	if err != nil {
		t.Fatalf("TTL returned error: %v", err)
	}
	if setTTL <= 0 || setTTL > time.Hour {
		t.Fatalf("set TTL = %v after touch, want a fresh ~1h instead of none", setTTL)
	}
}

// A live member whose Hash is entirely gone (eviction drop, external delete)
// must be rebuilt as a complete record, not as a last_seen-only stub: a stub
// would surface in the device list with empty ua/ip and a zero login_time, and
// would stop being swept by the phantom cleanup.
func TestTouchDeviceRebuildsMissingHashFully(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	if _, err := store.RegisterDevice(ctx, 42, "family-1", "old-ua", "10.0.0.1", now, time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	// The Hash disappears while the member stays (the live branch's scenario).
	if err := client.Del(ctx, store.Keys.Device("family-1")).Err(); err != nil {
		t.Fatalf("Del hash: %v", err)
	}
	later := now.Add(30 * time.Minute)
	if _, err := store.TouchDevice(ctx, 42, "family-1", "new-ua", "10.0.0.9", later, time.Hour, 5); err != nil {
		t.Fatalf("TouchDevice returned error: %v", err)
	}

	devices, err := store.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("devices = %#v, want exactly one", devices)
	}
	if devices[0].UA != "new-ua" || devices[0].IP != "10.0.0.9" {
		t.Fatalf("device meta = %+v, want the touch's ua/ip rebuilt", devices[0])
	}
	if devices[0].LoginTime.IsZero() {
		t.Fatalf("login_time is zero, want it rebuilt by the touch")
	}
}

// A refresh that arrives after the record TTL already expired resurrects the
// device with a fresh TTL and re-recorded metadata: the session is clearly
// still in use, and silently dropping the refresh would leave a working but
// invisible, unmanageable ghost session. Eviction is a different story — the
// evicted family is revoked by the service, so its refresh never reaches this
// code path.
func TestTouchDeviceResurrectsExpiredRecord(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	if _, err := store.RegisterDevice(ctx, 42, "family-1", "old-ua", "10.0.0.1", now, time.Second, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	time.Sleep(1100 * time.Millisecond) // let the record expire

	daysLater := now.Add(48 * time.Hour)
	if _, err := store.TouchDevice(ctx, 42, "family-1", "new-ua", "10.0.0.2", daysLater, time.Hour, 5); err != nil {
		t.Fatalf("TouchDevice returned error: %v", err)
	}

	devices, err := store.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(devices) != 1 || devices[0].DeviceID != "family-1" {
		t.Fatalf("devices = %#v, want the resurrected family-1", devices)
	}
	if devices[0].UA != "new-ua" || devices[0].IP != "10.0.0.2" {
		t.Fatalf("device meta = %+v, want the refresh's ua/ip", devices[0])
	}
	if !devices[0].LastSeen.Equal(daysLater) {
		t.Fatalf("last_seen = %v, want %v", devices[0].LastSeen, daysLater)
	}
	// The resurrected record carries a fresh TTL instead of a TTL-less orphan.
	ttl, err := client.TTL(ctx, store.Keys.Device("family-1")).Result()
	if err != nil {
		t.Fatalf("TTL returned error: %v", err)
	}
	if ttl <= 0 || ttl > time.Hour {
		t.Fatalf("resurrected TTL = %v, want about 1h", ttl)
	}
}

// Resurrecting re-enters the per-user cap: with the set already full (cap 2:
// B, C), an expired-but-still-refreshing device A comes back and displaces the
// oldest member B. The script reports the evicted ID so the caller revokes
// its family — without this a user at the cap with one expired device would
// silently end up with 3 live sessions.
func TestTouchDeviceResurrectEvictsOldestWhenAtCap(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	// A ages out after 1s; B and C fill the cap of 2.
	if _, err := store.RegisterDevice(ctx, 42, "family-A", "ua-a", "ip-a", now, time.Second, 2); err != nil {
		t.Fatalf("RegisterDevice(A) returned error: %v", err)
	}
	if _, err := store.RegisterDevice(ctx, 42, "family-B", "ua-b", "ip-b", now.Add(time.Minute), time.Hour, 2); err != nil {
		t.Fatalf("RegisterDevice(B) returned error: %v", err)
	}
	if _, err := store.RegisterDevice(ctx, 42, "family-C", "ua-c", "ip-c", now.Add(2*time.Minute), time.Hour, 2); err != nil {
		t.Fatalf("RegisterDevice(C) returned error: %v", err)
	}
	time.Sleep(1100 * time.Millisecond) // let A expire

	// A refreshes: resurrected, and B (oldest) is evicted to hold the cap.
	resurrected := now.Add(48 * time.Hour)
	evicted, err := store.TouchDevice(ctx, 42, "family-A", "ua-a", "ip-a", resurrected, time.Hour, 2)
	if err != nil {
		t.Fatalf("TouchDevice returned error: %v", err)
	}
	if evicted != "family-B" {
		t.Fatalf("evicted = %q, want family-B (the oldest member)", evicted)
	}
	devices, err := store.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("devices = %#v, want exactly 2 after resurrect+evict", devices)
	}
	if exists, err := client.Exists(ctx, store.Keys.Device("family-B")).Result(); err != nil || exists != 0 {
		t.Fatalf("evicted device hash exists = %v (err %v), want 0", exists, err)
	}
}

// A phantom member — set member whose Hash is gone (eviction drop, external
// delete, expiry skew) — must not occupy a cap slot: registering a new device
// sweeps it out without revoking its family (the record is lost, not the
// session; the device re-registers on its next refresh) and then holds the cap
// with real devices only.
func TestRegisterDeviceSweepsPhantomMembers(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	if _, err := store.RegisterDevice(ctx, 42, "family-A", "ua", "ip", now, time.Hour, 2); err != nil {
		t.Fatalf("RegisterDevice(A) returned error: %v", err)
	}
	// Kill A's Hash: the member stays, the record is gone.
	if err := client.Del(ctx, store.Keys.Device("family-A")).Err(); err != nil {
		t.Fatalf("Del hash: %v", err)
	}
	if _, err := store.RegisterDevice(ctx, 42, "family-B", "ua", "ip", now.Add(time.Minute), time.Hour, 2); err != nil {
		t.Fatalf("RegisterDevice(B) returned error: %v", err)
	}
	// C registers while the phantom A still holds a slot: A is swept, so B
	// (a real device) is NOT evicted.
	evicted, err := store.RegisterDevice(ctx, 42, "family-C", "ua", "ip", now.Add(2*time.Minute), time.Hour, 2)
	if err != nil {
		t.Fatalf("RegisterDevice(C) returned error: %v", err)
	}
	if evicted != "" {
		t.Fatalf("evicted = %q, want none — the phantom slot was swept, not a real device", evicted)
	}
	devices, err := store.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("devices = %#v, want exactly the two real devices B and C", devices)
	}
}

// The resurrect branch of TouchDevice sweeps phantoms too: a full set made of
// one phantom plus one real device must not push the real device out.
func TestTouchDeviceResurrectSweepsPhantomMembers(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	// A ages out after 1s; B fills the set with cap 2.
	if _, err := store.RegisterDevice(ctx, 42, "family-A", "ua", "ip", now, time.Second, 2); err != nil {
		t.Fatalf("RegisterDevice(A) returned error: %v", err)
	}
	if _, err := store.RegisterDevice(ctx, 42, "family-B", "ua", "ip", now.Add(time.Minute), time.Hour, 2); err != nil {
		t.Fatalf("RegisterDevice(B) returned error: %v", err)
	}
	// Kill B's Hash: a phantom member holding the second cap slot.
	if err := client.Del(ctx, store.Keys.Device("family-B")).Err(); err != nil {
		t.Fatalf("Del hash: %v", err)
	}
	time.Sleep(1100 * time.Millisecond) // let A expire

	// A resurrects: the phantom B is swept, so no real device is evicted.
	evicted, err := store.TouchDevice(ctx, 42, "family-A", "ua", "ip", now.Add(48*time.Hour), time.Hour, 2)
	if err != nil {
		t.Fatalf("TouchDevice returned error: %v", err)
	}
	if evicted != "" {
		t.Fatalf("evicted = %q, want none — the phantom slot was swept", evicted)
	}
	devices, err := store.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(devices) != 1 || devices[0].DeviceID != "family-A" {
		t.Fatalf("devices = %#v, want only the resurrected family-A", devices)
	}
}

// ListDevices skips (and removes) phantom members instead of showing a ghost
// row with no data.
func TestListDevicesSkipsPhantomMembers(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	if _, err := store.RegisterDevice(ctx, 42, "family-A", "ua", "ip", now, time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice(A) returned error: %v", err)
	}
	if _, err := store.RegisterDevice(ctx, 42, "family-B", "ua", "ip", now.Add(time.Minute), time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice(B) returned error: %v", err)
	}
	if err := client.Del(ctx, store.Keys.Device("family-B")).Err(); err != nil {
		t.Fatalf("Del hash: %v", err)
	}

	devices, err := store.ListDevices(ctx, 42)
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(devices) != 1 || devices[0].DeviceID != "family-A" {
		t.Fatalf("devices = %#v, want only family-A; the phantom B must be skipped", devices)
	}
	// The phantom member is gone from the set as well, not just hidden.
	if exists, err := client.ZScore(ctx, store.Keys.Devices(42), "family-B").Result(); err != goredis.Nil {
		t.Fatalf("phantom member B still in set: score = %v (err %v), want gone", exists, err)
	}
}

func TestRemoveDevice(t *testing.T) {
	client := testutil.StartRedis(t)
	ctx := context.Background()
	store := Store{Client: client, Keys: NewKeys("sast-link:test")}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	if _, err := store.RegisterDevice(ctx, 42, "family-1", "ua", "ip", now, time.Hour, 5); err != nil {
		t.Fatalf("RegisterDevice returned error: %v", err)
	}
	if _, err := store.RegisterDevice(ctx, 42, "family-2", "ua", "ip", now.Add(time.Minute), time.Hour, 5); err != nil {
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
		if _, err := store.RegisterDevice(ctx, 42, id, "ua", "ip", now.Add(time.Duration(i)*time.Minute), time.Hour, 5); err != nil {
			t.Fatalf("RegisterDevice %s returned error: %v", id, err)
		}
	}
	// Another user's devices must survive a per-user clear.
	if _, err := store.RegisterDevice(ctx, 7, "family-7", "ua", "ip", now, time.Hour, 5); err != nil {
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

	if _, err := store.RegisterDevice(ctx, 42, "family-1", "ua", "ip", now, time.Hour, 5); err != nil {
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
