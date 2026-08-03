package session

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
)

type ListDevicesInput struct {
	UserID int64
}

type ListDevicesResult struct {
	Devices []DeviceRecord
}

type LogoutDeviceInput struct {
	UserID    int64
	DeviceID  string
	ClientIP  string
	UserAgent string
}

type LogoutDeviceResult struct {
	DeviceID string
}

// ListDevices returns the caller's logged-in devices, newest first. Device
// records are Redis-only operational state (PRD §6.1), so an unavailable store
// degrades to an empty list with a WARN instead of an error: the user loses the
// view, never the ability to log in again.
func (s Service) ListDevices(ctx context.Context, input ListDevicesInput) (*ListDevicesResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidInput, "设备列表参数无效", nil)
	}
	if s.Devices == nil {
		return &ListDevicesResult{Devices: []DeviceRecord{}}, nil
	}
	devices, err := s.Devices.ListDevices(ctx, input.UserID)
	if err != nil {
		slog.WarnContext(ctx, "list devices failed", "user_id", input.UserID, "error", err)
		return &ListDevicesResult{Devices: []DeviceRecord{}}, nil
	}
	return &ListDevicesResult{Devices: devices}, nil
}

// LogoutDevice revokes one device's whole token family and removes its device
// record. The device ID is the family ID, so the DB revoke below reuses the
// exact machinery of logout; the ownership check must pass first because
// RevokeFamily itself trusts its caller.
func (s Service) LogoutDevice(ctx context.Context, input LogoutDeviceInput) (*LogoutDeviceResult, error) {
	deviceID := strings.TrimSpace(input.DeviceID)
	if input.UserID <= 0 || deviceID == "" {
		return nil, newError(ErrInvalidInput, "登出设备参数无效", nil)
	}
	if err := s.checkEndpointLimit(ctx, s.DeviceLimiter, "device", "user:"+strconv.FormatInt(input.UserID, 10)); err != nil {
		return nil, err
	}
	if s.Devices == nil {
		return nil, newError(ErrDependencyUnavailable, "设备服务不可用", nil)
	}
	// Fail-closed ownership gate: an unreadable device set proves nothing, so
	// Redis trouble must reject the revoke rather than skip the check.
	owned, err := s.Devices.DeviceOwnedBy(ctx, input.UserID, deviceID)
	if err != nil {
		return nil, newError(ErrDependencyUnavailable, "设备服务暂不可用", err)
	}
	if !owned {
		return nil, newError(ErrDeviceNotFound, "设备不存在", nil)
	}
	now := s.now()
	entries, err := s.Tokens.RevokeFamily(ctx, deviceID, now)
	if err != nil {
		return nil, newError(ErrInternal, "撤销设备会话失败", err)
	}
	s.deliverBlacklist(ctx, entries, now)
	// The family is dead; the record cleanup is best-effort and must not fail
	// the call the user sees as a successful logout.
	if err := s.Devices.RemoveDevice(ctx, input.UserID, deviceID); err != nil {
		slog.WarnContext(ctx, "remove device after logout failed", "user_id", input.UserID, "device_id", deviceID, "error", err)
	}
	if auditErr := s.audit(ctx, &input.UserID, "logout_device", "session", &deviceID, true, 0, input.ClientIP, input.UserAgent, map[string]any{"device_id": deviceID}); auditErr != nil {
		slog.Error("audit logout device", "user_id", input.UserID, "device_id", deviceID, "error", auditErr)
	}
	return &LogoutDeviceResult{DeviceID: deviceID}, nil
}
