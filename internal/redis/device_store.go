package redis

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// DeviceInfo is one logged-in device record, as stored in the device Hash.
// login_time / last_seen are serialized as RFC3339 strings.
type DeviceInfo struct {
	DeviceID  string
	UA        string
	IP        string
	LoginTime time.Time
	LastSeen  time.Time
}

// Devices returns the sorted set holding a user's device IDs, scored by login
// timestamp. The member is the device ID, which the session service binds to
// the token family ID so device lifecycle and session lifecycle stay one.
func (k Keys) Devices(userID int64) string {
	return k.join("devices", strconv.FormatInt(userID, 10))
}

// Device returns the Hash holding one device's details.
func (k Keys) Device(deviceID string) string {
	return k.join("device", deviceID)
}

// deviceHashKeyPrefix is the shared prefix of every device Hash key, passed
// into Lua scripts that derive member keys from it at runtime.
func (k Keys) deviceHashKeyPrefix() string {
	return k.join("device") + ":"
}

// RegisterDevice records a login as a device: ZADD to the user's device sorted
// set, HSET the device Hash, evicting the oldest device when the set exceeds
// limit — all atomically, so concurrent logins cannot push the set past the
// cap. The evicted device's Hash is deleted by the caller.
//
// The returned device ID is the evicted member ("" within the cap). The caller
// must revoke that device's token family: eviction is the "最多 5 台同时登录"
// enforcement (PRD §6.1), and a family whose record vanished while its tokens
// stayed live would become an unmanageable ghost session.
//
// Both keys get ttl; TouchDevice deliberately does not refresh it, so a device
// that stops refreshing falls out of the set on its own.
func (s Store) RegisterDevice(
	ctx context.Context,
	userID int64,
	deviceID, ua, ip string,
	now time.Time,
	ttl time.Duration,
	limit int,
) (string, error) {
	if s.Client == nil || userID <= 0 || deviceID == "" || ttl <= 0 || limit <= 0 {
		return "", fmt.Errorf("register device: %w", ErrInvalidArgument)
	}
	seconds := int(ttl.Seconds())
	if seconds <= 0 {
		return "", fmt.Errorf("register device: %w", ErrInvalidArgument)
	}
	loginTime := now.UTC().Format(time.RFC3339)
	keys := []string{
		s.Keys.Devices(userID),
		s.Keys.Device(deviceID),
		s.Keys.deviceHashKeyPrefix(),
	}
	evicted, err := s.Client.Eval(ctx, registerDeviceScript, keys,
		now.UnixMilli(), deviceID, seconds, ua, ip, loginTime, limit,
	).Text()
	if err != nil {
		return "", fmt.Errorf("register device eval: %w", err)
	}
	if evicted != "" {
		if err := s.Client.Del(ctx, s.Keys.Device(evicted)).Err(); err != nil {
			return evicted, fmt.Errorf("delete evicted device hash: %w", err)
		}
	}
	return evicted, nil
}

// registerDeviceScript adds the device, refreshes both TTLs, and evicts the
// oldest member once the set exceeds the per-user cap. Before the cap check it
// sweeps phantom members (set members whose Hash is gone) out of the set
// without revoking their families, so a phantom cannot occupy a cap slot and
// force the eviction of a real device. Returns the evicted device ID ("" when
// nothing was evicted).
const registerDeviceScript = `
redis.call("ZADD", KEYS[1], ARGV[1], ARGV[2])
redis.call("EXPIRE", KEYS[1], tonumber(ARGV[3]))
redis.call("HSET", KEYS[2], "ua", ARGV[4], "ip", ARGV[5], "login_time", ARGV[6], "last_seen", ARGV[6])
redis.call("EXPIRE", KEYS[2], tonumber(ARGV[3]))
local candidates = redis.call("ZRANGE", KEYS[1], 0, -1)
for _, id in ipairs(candidates) do
  if redis.call("EXISTS", KEYS[3] .. id) == 0 then
    redis.call("ZREM", KEYS[1], id)
  end
end
local count = redis.call("ZCARD", KEYS[1])
if count > tonumber(ARGV[7]) then
  local evicted = redis.call("ZRANGE", KEYS[1], 0, 0)
  redis.call("ZREMRANGEBYRANK", KEYS[1], 0, 0)
  return evicted[1]
end
return ""
`

// TouchDevice updates a device's last_seen on token refresh without extending
// the live record's TTL, so an active device cannot stay in the set forever by
// refreshing. A refresh after the record expired instead resurrects it with a
// fresh TTL and re-enters the per-user cap (evicting the oldest member past
// limit, like RegisterDevice): silently dropping the refresh would leave an
// invisible, unloggable ghost session, and skipping the cap check would allow
// more live sessions than the "最多 5 台同时登录" limit.
func (s Store) TouchDevice(ctx context.Context, userID int64, deviceID, ua, ip string, now time.Time, ttl time.Duration, limit int) (string, error) {
	if s.Client == nil || userID <= 0 || deviceID == "" || ttl <= 0 || limit <= 0 {
		return "", fmt.Errorf("touch device: %w", ErrInvalidArgument)
	}
	seconds := int(ttl.Seconds())
	if seconds <= 0 {
		return "", fmt.Errorf("touch device: %w", ErrInvalidArgument)
	}
	lastSeen := now.UTC().Format(time.RFC3339)
	values, err := s.Client.Eval(ctx, touchDeviceScript, []string{
		s.Keys.Devices(userID),
		s.Keys.Device(deviceID),
		s.Keys.deviceHashKeyPrefix(),
	}, deviceID, lastSeen, seconds, ua, ip, now.UnixMilli(), limit).Slice()
	if err != nil {
		return "", fmt.Errorf("touch device eval: %w", err)
	}
	evicted := ""
	if len(values) >= 2 {
		if raw, ok := values[1].(string); ok {
			evicted = raw
		}
	}
	if evicted != "" {
		if err := s.Client.Del(ctx, s.Keys.Device(evicted)).Err(); err != nil {
			return evicted, fmt.Errorf("delete evicted device hash: %w", err)
		}
	}
	return evicted, nil
}

// touchDeviceScript refreshes last_seen for a live member; a refresh of a
// member that already aged out of the set resurrects it like RegisterDevice,
// including evicting the oldest member past the per-user cap. Returns
// {status, evicted device ID}: status 1 = live record touched (no eviction),
// status 0 = resurrected (evicted is "" unless the cap was exceeded).
//
// The live branch re-applies a TTL only when missing, so a rebuilt Hash never
// becomes never-expiring and a member cannot outlive its record as a zombie;
// a rebuilt Hash restores login_time from the ZSET score so the displayed time
// stays consistent with its sort position. The resurrect branch sweeps phantom
// members before the cap check so they cannot occupy cap slots.
const touchDeviceScript = `
local score = redis.call("ZSCORE", KEYS[1], ARGV[1])
-- unix_ms_to_rfc3339 renders a Unix-millis score back into the RFC3339
-- "2006-01-02T15:04:05Z" shape Go stores in the Hash, so a rebuilt login_time
-- matches the sort score exactly (Redis Lua has no os.date; this is the
-- civil-from-days algorithm).
local function unix_ms_to_rfc3339(ms)
  local sec = math.floor(ms / 1000)
  local days = math.floor(sec / 86400)
  local sod = sec % 86400
  local z = days + 719468
  local era = math.floor(z / 146097)
  local doe = z - era * 146097
  local yoe = math.floor((doe - math.floor(doe / 1460) + math.floor(doe / 36524) - math.floor(doe / 146096)) / 365)
  local y = yoe + era * 400
  local doy = doe - (365 * yoe + math.floor(yoe / 4) - math.floor(yoe / 100))
  local mp = math.floor((5 * doy + 2) / 153)
  local d = doy - math.floor((153 * mp + 2) / 5) + 1
  local m = mp + 3 - 12 * math.floor(mp / 10)
  y = y + math.floor(mp / 10)
  local hh = math.floor(sod / 3600)
  local mm = math.floor((sod % 3600) / 60)
  local ss = sod % 60
  return string.format("%04d-%02d-%02dT%02d:%02d:%02dZ", y, m, d, hh, mm, ss)
end
if score then
  if redis.call("EXISTS", KEYS[2]) == 0 then
    local login_time = unix_ms_to_rfc3339(score)
    redis.call("HSET", KEYS[2], "ua", ARGV[4], "ip", ARGV[5], "login_time", login_time, "last_seen", ARGV[2])
  else
    redis.call("HSET", KEYS[2], "last_seen", ARGV[2])
  end
  if redis.call("TTL", KEYS[2]) < 0 then
    redis.call("EXPIRE", KEYS[2], tonumber(ARGV[3]))
  end
  if redis.call("TTL", KEYS[1]) < 0 then
    redis.call("EXPIRE", KEYS[1], tonumber(ARGV[3]))
  end
  return {1, ""}
end
redis.call("ZADD", KEYS[1], ARGV[6], ARGV[1])
redis.call("EXPIRE", KEYS[1], tonumber(ARGV[3]))
redis.call("HSET", KEYS[2], "ua", ARGV[4], "ip", ARGV[5], "login_time", ARGV[2], "last_seen", ARGV[2])
redis.call("EXPIRE", KEYS[2], tonumber(ARGV[3]))
local candidates = redis.call("ZRANGE", KEYS[1], 0, -1)
for _, id in ipairs(candidates) do
  if redis.call("EXISTS", KEYS[3] .. id) == 0 then
    redis.call("ZREM", KEYS[1], id)
  end
end
local count = redis.call("ZCARD", KEYS[1])
if count > tonumber(ARGV[7]) then
  local evicted = redis.call("ZRANGE", KEYS[1], 0, 0)
  redis.call("ZREMRANGEBYRANK", KEYS[1], 0, 0)
  return {0, evicted[1]}
end
return {0, ""}
`

// RemoveDevice removes one device: ZREM from the user's set and DEL its Hash.
// Used by logout, which revokes the token family first (the device record is
// the tail of that operation and its absence never blocks the logout).
//
// INVARIANT: the caller must already have proven that deviceID belongs to
// userID — the Hash key holds no user dimension and cannot tell users apart.
func (s Store) RemoveDevice(ctx context.Context, userID int64, deviceID string) error {
	if s.Client == nil || userID <= 0 || deviceID == "" {
		return fmt.Errorf("remove device: %w", ErrInvalidArgument)
	}
	if err := s.Client.Eval(ctx, removeDeviceScript, []string{
		s.Keys.Devices(userID),
		s.Keys.Device(deviceID),
	}, deviceID).Err(); err != nil {
		return fmt.Errorf("remove device eval: %w", err)
	}
	return nil
}

const removeDeviceScript = `
redis.call("ZREM", KEYS[1], ARGV[1])
redis.call("DEL", KEYS[2])
return 1
`

// RemoveAllDevices clears every device of a user in one script: read the set,
// delete each device Hash, then drop the set itself. Used by password
// change/reset, which revokes every session in the same transaction.
func (s Store) RemoveAllDevices(ctx context.Context, userID int64) error {
	if s.Client == nil || userID <= 0 {
		return fmt.Errorf("remove all devices: %w", ErrInvalidArgument)
	}
	if err := s.Client.Eval(ctx, removeAllDevicesScript, []string{
		s.Keys.Devices(userID),
		s.Keys.deviceHashKeyPrefix(),
	}).Err(); err != nil {
		return fmt.Errorf("remove all devices eval: %w", err)
	}
	return nil
}

const removeAllDevicesScript = `
local members = redis.call("ZRANGE", KEYS[1], 0, -1)
redis.call("DEL", KEYS[1])
for _, id in ipairs(members) do
  redis.call("DEL", KEYS[2] .. id)
end
return #members
`

// ListDevices returns every device of a user, newest login first. The sorted
// set's member score is the login timestamp; the Hash carries ua/ip and both
// timestamps. A missing set is an empty list, and an orphaned Hash (set gone,
// record left) simply cannot be listed — the records are operational state, not
// authoritative data. The script always returns a (possibly empty) table for a
// missing key, so there is deliberately no goredis.Nil branch here.
func (s Store) ListDevices(ctx context.Context, userID int64) ([]DeviceInfo, error) {
	if s.Client == nil || userID <= 0 {
		return nil, fmt.Errorf("list devices: %w", ErrInvalidArgument)
	}
	values, err := s.Client.Eval(ctx, listDevicesScript, []string{
		s.Keys.Devices(userID),
		s.Keys.deviceHashKeyPrefix(),
	}).Slice()
	if err != nil {
		return nil, fmt.Errorf("list devices eval: %w", err)
	}
	const fieldsPerDevice = 6
	devices := make([]DeviceInfo, 0, len(values)/fieldsPerDevice)
	for i := 0; i+fieldsPerDevice <= len(values); i += fieldsPerDevice {
		deviceID, ok := values[i].(string)
		if !ok {
			continue
		}
		info := DeviceInfo{DeviceID: deviceID}
		if raw, ok := values[i+2].(string); ok {
			info.UA = raw
		}
		if raw, ok := values[i+3].(string); ok {
			info.IP = raw
		}
		if raw, ok := values[i+4].(string); ok {
			info.LoginTime = parseRFC3339(raw)
		}
		if raw, ok := values[i+5].(string); ok {
			info.LastSeen = parseRFC3339(raw)
		}
		devices = append(devices, info)
	}
	return devices, nil
}

// listDevicesScript returns a flat array of {device_id, score, ua, ip,
// login_time, last_seen} per device, newest first (ZREVRANGE). Hash fields are
// read individually so a missing or partial Hash degrades to empty strings;
// members whose Hash is entirely gone are skipped, since a record with no data
// would render as an unactionable ghost row.
const listDevicesScript = `
local members = redis.call("ZREVRANGE", KEYS[1], 0, -1, "WITHSCORES")
local result = {}
for i = 1, #members, 2 do
  if redis.call("EXISTS", KEYS[2] .. members[i]) == 0 then
    redis.call("ZREM", KEYS[1], members[i])
  else
    local fields = redis.call("HGETALL", KEYS[2] .. members[i])
    local h = {}
    for j = 1, #fields, 2 do h[fields[j]] = fields[j + 1] end
    result[#result + 1] = members[i]
    result[#result + 1] = members[i + 1]
    result[#result + 1] = h["ua"] or ""
    result[#result + 1] = h["ip"] or ""
    result[#result + 1] = h["login_time"] or ""
    result[#result + 1] = h["last_seen"] or ""
  end
end
return result
`

// DeviceOwnedBy reports whether deviceID is a member of the user's device set.
// This is the ownership gate for "logout a specific device": a false positive
// would let one user kill another's sessions, so an unreadable set fails closed.
func (s Store) DeviceOwnedBy(ctx context.Context, userID int64, deviceID string) (bool, error) {
	if s.Client == nil || userID <= 0 || deviceID == "" {
		return false, fmt.Errorf("device ownership: %w", ErrInvalidArgument)
	}
	owned, err := s.Client.Eval(ctx, deviceOwnedByScript,
		[]string{s.Keys.Devices(userID)}, deviceID,
	).Int64()
	if err != nil {
		return false, fmt.Errorf("device ownership eval: %w", err)
	}
	return owned == 1, nil
}

const deviceOwnedByScript = `
local score = redis.call("ZSCORE", KEYS[1], ARGV[1])
if score then return 1 end
return 0
`

func parseRFC3339(raw string) time.Time {
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed
}
