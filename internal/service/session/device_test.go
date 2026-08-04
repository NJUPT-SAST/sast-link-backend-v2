package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/mailer"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

type fakeDevices struct {
	registrations []deviceRegistration
	touches       []deviceRegistration
	removed       []string
	removedAll    []int64
	records       []DeviceRecord
	owned         bool
	registerErr   error
	touchErr      error
	removeErr     error
	removeAllErr  error
	listErr       error
	ownedErr      error
	// evicted is returned by RegisterDevice when no error is set, simulating
	// the per-user cap displacing the oldest device.
	evicted string
	// touchEvicted is returned by TouchDevice, simulating a resurrected
	// record displacing the oldest device past the per-user cap.
	touchEvicted string
}

type deviceRegistration struct {
	userID   int64
	deviceID string
	ua       string
	ip       string
}

func (f *fakeDevices) RegisterDevice(_ context.Context, userID int64, deviceID, ua, ip string, _ time.Time) (string, error) {
	f.registrations = append(f.registrations, deviceRegistration{userID: userID, deviceID: deviceID, ua: ua, ip: ip})
	if f.registerErr != nil {
		// Simulate a partial failure: the script already evicted inside Redis,
		// but a later step (evicted-hash delete) failed. The evicted family must
		// still be revoked.
		return f.evicted, f.registerErr
	}
	return f.evicted, nil
}

func (f *fakeDevices) TouchDevice(_ context.Context, userID int64, deviceID, ua, ip string, _ time.Time) (string, error) {
	if f.touchErr != nil {
		return "", f.touchErr
	}
	f.touches = append(f.touches, deviceRegistration{userID: userID, deviceID: deviceID, ua: ua, ip: ip})
	return f.touchEvicted, nil
}

func (f *fakeDevices) RemoveDevice(_ context.Context, userID int64, deviceID string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	f.removed = append(f.removed, deviceID)
	return nil
}

func (f *fakeDevices) RemoveAllDevices(_ context.Context, userID int64) error {
	if f.removeAllErr != nil {
		return f.removeAllErr
	}
	f.removedAll = append(f.removedAll, userID)
	return nil
}

func (f *fakeDevices) ListDevices(_ context.Context, userID int64) ([]DeviceRecord, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.records, nil
}

func (f *fakeDevices) DeviceOwnedBy(_ context.Context, userID int64, deviceID string) (bool, error) {
	if f.ownedErr != nil {
		return false, f.ownedErr
	}
	return f.owned, nil
}

func withDevices(service Service, devices *fakeDevices) Service {
	service.Devices = devices
	return service
}

func TestLoginRegistersDeviceFromFamilyAndRequestMeta(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	devices := &fakeDevices{}
	service = withDevices(service, devices)
	_, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret", ClientIP: "10.0.0.7", UserAgent: "test-agent/1.0"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if len(devices.registrations) != 1 {
		t.Fatalf("registrations = %#v, want exactly one", devices.registrations)
	}
	reg := devices.registrations[0]
	if reg.userID != 42 {
		t.Fatalf("registration user = %d, want 42", reg.userID)
	}
	family := reg.deviceID
	if family == "" {
		t.Fatal("device ID is empty")
	}
	tokens := service.Tokens.(*fakeTokens)
	if tokens.createdAccess.FamilyID == nil || *tokens.createdAccess.FamilyID != family {
		t.Fatalf("registered device %q does not match created family %v", family, tokens.createdAccess.FamilyID)
	}
	if reg.ua != "test-agent/1.0" || reg.ip != "10.0.0.7" {
		t.Fatalf("registration meta = %+v, want ua/ip from request", reg)
	}
}

func TestLoginSucceedsWhenDeviceRegistrationFails(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	devices := &fakeDevices{registerErr: errors.New("redis down")}
	service = withDevices(service, devices)
	result, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error, want fail-open session: %v", err)
	}
	if result.AccessToken == "" {
		t.Fatal("login produced no access token")
	}
}

// Eviction is the "最多 5 台同时登录" enforcement: when the cap displaces the
// oldest device, its whole token family must be revoked so the displaced
// session cannot keep refreshing invisibly.
func TestLoginRevokesEvictedDeviceFamily(t *testing.T) {
	service, _, _, tokens, audit, _ := newTestService(t)
	devices := &fakeDevices{evicted: "family-0"}
	service = withDevices(service, devices)
	if _, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"}); err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if len(tokens.revokedFamilies) != 1 || tokens.revokedFamilies[0] != "family-0" {
		t.Fatalf("revoked families = %#v, want the evicted family-0", tokens.revokedFamilies)
	}
	if len(devices.removed) != 1 || devices.removed[0] != "family-0" {
		t.Fatalf("removed = %#v, want the evicted record cleaned after the revoke", devices.removed)
	}
	// The eviction is a session-killing event like logout; it must be audited
	// so the trail explains every dead session.
	var evictedAudit *model.AuditLog
	for i := range audit.entries {
		if audit.entries[i].Action == "evict_device" {
			evictedAudit = &audit.entries[i]
		}
	}
	if evictedAudit == nil || evictedAudit.ResourceID == nil || *evictedAudit.ResourceID != "family-0" || evictedAudit.Success == nil || !*evictedAudit.Success {
		t.Fatalf("evict_device audit = %+v, want success with resource family-0", evictedAudit)
	}
}

// A device-store error must not lose the eviction: the record write may have
// partially succeeded (set updated, hash delete failed), so the evicted family
// is still revoked on the error path.
func TestLoginRevokesEvictedFamilyEvenWhenRegistrationErrs(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)
	devices := &fakeDevices{registerErr: errors.New("redis down"), evicted: "family-0"}
	service = withDevices(service, devices)
	if _, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"}); err != nil {
		t.Fatalf("Login returned error, want fail-open session: %v", err)
	}
	if len(tokens.revokedFamilies) != 1 || tokens.revokedFamilies[0] != "family-0" {
		t.Fatalf("revoked families = %#v, want the evicted family-0 even on store error", tokens.revokedFamilies)
	}
}

func TestLoginSucceedsWhenEvictedRevokeFails(t *testing.T) {
	service, _, _, tokens, _, _ := newTestService(t)
	devices := &fakeDevices{evicted: "family-0"}
	service = withDevices(service, devices)
	tokens.revokeErr = errors.New("db down")
	result, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error, want fail-open session: %v", err)
	}
	if result.AccessToken == "" {
		t.Fatal("login produced no access token")
	}
}

func TestRegisterRegistersDevice(t *testing.T) {
	service := newRegisterService(t)
	devices := &fakeDevices{}
	service = withDevices(service, devices)
	tickets := service.RegisterTicket.(*fakeRegisterTicketStore)
	if err := tickets.SaveRegisterTicket(context.Background(), "reg_xxx", "new@sast.fun", time.Minute); err != nil {
		t.Fatalf("save register ticket: %v", err)
	}
	_, err := service.Register(context.Background(), RegisterInput{
		RegisterTicket: "reg_xxx",
		Password:       "newpassword",
		Name:           "New User",
		StudentID:      "B24040099",
		PhoneNumber:    "13800138000",
		QQNumber:       "10000",
		College:        string(model.CollegeOther),
		Major:          "CS",
		ClientIP:       "10.0.0.9",
		UserAgent:      "register-agent",
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if len(devices.registrations) != 1 || devices.registrations[0].userID == 0 {
		t.Fatalf("registrations = %#v, want the initial session registered as a device", devices.registrations)
	}
	if devices.registrations[0].ua != "register-agent" || devices.registrations[0].ip != "10.0.0.9" {
		t.Fatalf("registration meta = %+v", devices.registrations[0])
	}
}

func TestRefreshTouchesDevice(t *testing.T) {
	service := newRegisterService(t)
	devices := &fakeDevices{}
	service = withDevices(service, devices)
	pair, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	result, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: pair.RefreshToken, UserAgent: "browser/9", ClientIP: "10.0.0.9"})
	if err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	if result.AccessToken == "" {
		t.Fatal("refresh produced no access token")
	}
	if len(devices.touches) != 1 || devices.touches[0].deviceID == "" {
		t.Fatalf("touches = %#v, want the family of the refreshed session", devices.touches)
	}
	tokens := service.Tokens.(*fakeTokens)
	if tokens.rotatedRefresh.FamilyID != devices.touches[0].deviceID {
		t.Fatalf("touched device %q != rotated family %q", devices.touches[0].deviceID, tokens.rotatedRefresh.FamilyID)
	}
	if devices.touches[0].ua != "browser/9" || devices.touches[0].ip != "10.0.0.9" {
		t.Fatalf("touch meta = %+v, want ua/ip from the refresh request", devices.touches[0])
	}
}

func TestRefreshSucceedsWhenTouchFails(t *testing.T) {
	service := newRegisterService(t)
	devices := &fakeDevices{touchErr: errors.New("redis down")}
	service = withDevices(service, devices)
	pair, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if _, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: pair.RefreshToken}); err != nil {
		t.Fatalf("Refresh returned error, want fail-open rotation: %v", err)
	}
}

// A refresh that resurrects an expired record re-enters the per-user cap:
// when the set was already full, the resurrected device displaces the oldest
// member and the displaced family is revoked, exactly like login eviction.
// Without the revoke a user at the 5-device cap with one expired-but-still-
// refreshing device would silently hold 6 live sessions.
func TestRefreshRevokesEvictedFamilyOnResurrect(t *testing.T) {
	service := newRegisterService(t)
	devices := &fakeDevices{touchEvicted: "family-oldest"}
	service = withDevices(service, devices)
	pair, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if _, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: pair.RefreshToken}); err != nil {
		t.Fatalf("Refresh returned error, want fail-open rotation: %v", err)
	}
	tokens := service.Tokens.(*fakeTokens)
	if len(tokens.revokedFamilies) != 1 || tokens.revokedFamilies[0] != "family-oldest" {
		t.Fatalf("revoked families = %#v, want the family displaced by the resurrected device", tokens.revokedFamilies)
	}
	if len(devices.removed) != 1 || devices.removed[0] != "family-oldest" {
		t.Fatalf("removed = %#v, want the displaced record cleaned after the revoke", devices.removed)
	}
}

// The eviction driven by a resurrecting refresh must not block the rotation
// itself: a Redis/database outage already costs the refresh nothing, and the
// displaced family stays live only until the operator notices — WARN only.
func TestRefreshSucceedsWhenEvictedRevokeFails(t *testing.T) {
	service := newRegisterService(t)
	devices := &fakeDevices{touchEvicted: "family-oldest"}
	service = withDevices(service, devices)
	pair, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	tokens := service.Tokens.(*fakeTokens)
	tokens.revokeErr = errors.New("db down")
	if _, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: pair.RefreshToken}); err != nil {
		t.Fatalf("Refresh returned error, want fail-open rotation: %v", err)
	}
}

// A refresh whose family was revoked between the pre-checks and the rotation (a
// concurrent logout or eviction) is doomed: the touch may have resurrected and
// evicted a device, but the rotation then fails. The eviction revoke is
// deferred until the rotation commits, so a doomed refresh must not revoke a
// different, healthy device's family as collateral.
func TestRefreshRotationFailureDoesNotRevokeEvictedFamily(t *testing.T) {
	service := newRegisterService(t)
	devices := &fakeDevices{touchEvicted: "family-other"}
	service = withDevices(service, devices)
	pair, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	tokens := service.Tokens.(*fakeTokens)
	// The family was revoked concurrently, so the rotation must fail as a replay.
	tokens.rotateErr = repository.ErrTokenReplay
	if _, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: pair.RefreshToken}); err == nil {
		t.Fatal("Refresh returned nil error, want the doomed rotation to fail")
	}
	for _, family := range tokens.revokedFamilies {
		if family == "family-other" {
			t.Fatalf("revoked families = %#v, doomed refresh revoked the unrelated evicted family", tokens.revokedFamilies)
		}
	}
	for _, removed := range devices.removed {
		if removed == "family-other" {
			t.Fatalf("removed = %#v, doomed refresh cleaned the unrelated evicted record", devices.removed)
		}
	}
}

func TestLogoutRemovesDevice(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	devices := &fakeDevices{}
	service = withDevices(service, devices)
	pair, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	tokens := service.Tokens.(*fakeTokens)
	if _, err := service.Logout(context.Background(), LogoutInput{
		PrincipalJTI:    tokens.createdAccess.TokenID,
		PrincipalUserID: 42,
		RefreshToken:    pair.RefreshToken,
	}); err != nil {
		t.Fatalf("Logout returned error: %v", err)
	}
	if len(devices.removed) != 1 || devices.removed[0] != *tokens.createdAccess.FamilyID {
		t.Fatalf("removed = %#v, want the revoked family %q", devices.removed, *tokens.createdAccess.FamilyID)
	}
}

func TestLogoutSucceedsWhenDeviceRemoveFails(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	devices := &fakeDevices{removeErr: errors.New("redis down")}
	service = withDevices(service, devices)
	pair, err := service.Login(context.Background(), LoginInput{Identifier: "user@njupt.edu.cn", Password: "secret"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	tokens := service.Tokens.(*fakeTokens)
	if _, err := service.Logout(context.Background(), LogoutInput{
		PrincipalJTI:    tokens.createdAccess.TokenID,
		PrincipalUserID: 42,
		RefreshToken:    pair.RefreshToken,
	}); err != nil {
		t.Fatalf("Logout returned error, want fail-open logout: %v", err)
	}
}

func TestChangePasswordClearsAllDevices(t *testing.T) {
	service := newRegisterService(t)
	devices := &fakeDevices{}
	service = withDevices(service, devices)
	if _, err := service.ChangePassword(context.Background(), ChangePasswordInput{UserID: 42, OldPassword: "secret", NewPassword: "brand-new-password"}); err != nil {
		t.Fatalf("ChangePassword returned error: %v", err)
	}
	if len(devices.removedAll) != 1 || devices.removedAll[0] != 42 {
		t.Fatalf("removedAll = %#v, want user 42", devices.removedAll)
	}
}

func TestResetPasswordClearsAllDevices(t *testing.T) {
	service := newRegisterService(t)
	devices := &fakeDevices{}
	service = withDevices(service, devices)
	codes := service.VerificationCode.(*fakeVerificationCodeStore)
	if err := codes.SaveVerificationCode(context.Background(), string(mailer.VerificationPurposeResetPassword), "user@njupt.edu.cn", "123456", time.Minute); err != nil {
		t.Fatalf("save code: %v", err)
	}
	if _, err := service.ResetPassword(context.Background(), ResetPasswordInput{Email: "user@njupt.edu.cn", Code: "123456", Password: "brand-new-password"}); err != nil {
		t.Fatalf("ResetPassword returned error: %v", err)
	}
	if len(devices.removedAll) != 1 || devices.removedAll[0] != 42 {
		t.Fatalf("removedAll = %#v, want user 42", devices.removedAll)
	}
}

func TestChangePasswordSucceedsWhenDeviceClearFails(t *testing.T) {
	service := newRegisterService(t)
	devices := &fakeDevices{removeAllErr: errors.New("redis down")}
	service = withDevices(service, devices)
	if _, err := service.ChangePassword(context.Background(), ChangePasswordInput{UserID: 42, OldPassword: "secret", NewPassword: "brand-new-password"}); err != nil {
		t.Fatalf("ChangePassword returned error, want fail-open password change: %v", err)
	}
}

func TestListDevicesReturnsRecords(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	devices := &fakeDevices{records: []DeviceRecord{
		{DeviceID: "newer", UA: "browser", IP: "10.0.0.1", LoginTime: time.Now()},
		{DeviceID: "older", UA: "app", IP: "10.0.0.2", LoginTime: time.Now().Add(-time.Hour)},
	}}
	service = withDevices(service, devices)
	result, err := service.ListDevices(context.Background(), ListDevicesInput{UserID: 42})
	if err != nil {
		t.Fatalf("ListDevices returned error: %v", err)
	}
	if len(result.Devices) != 2 || result.Devices[0].DeviceID != "newer" {
		t.Fatalf("devices = %#v, want the store's records in order", result.Devices)
	}
}

func TestListDevicesDegradesToEmptyOnStoreError(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	devices := &fakeDevices{listErr: errors.New("redis down")}
	service = withDevices(service, devices)
	result, err := service.ListDevices(context.Background(), ListDevicesInput{UserID: 42})
	if err != nil {
		t.Fatalf("ListDevices returned error, want fail-open empty list: %v", err)
	}
	if result == nil || len(result.Devices) != 0 {
		t.Fatalf("devices = %#v, want empty list", result.Devices)
	}
}

func TestListDevicesRejectsInvalidUser(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	_, err := service.ListDevices(context.Background(), ListDevicesInput{UserID: 0})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

func TestLogoutDeviceRevokesFamilyAndRemovesRecord(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	devices := &fakeDevices{owned: true}
	service = withDevices(service, devices)
	tokens := service.Tokens.(*fakeTokens)
	audit := service.Audit.(*fakeAudit)

	result, err := service.LogoutDevice(context.Background(), LogoutDeviceInput{UserID: 42, DeviceID: "family-123"})
	if err != nil {
		t.Fatalf("LogoutDevice returned error: %v", err)
	}
	if result.DeviceID != "family-123" {
		t.Fatalf("result = %+v", result)
	}
	if len(tokens.revokedFamilies) != 1 || tokens.revokedFamilies[0] != "family-123" {
		t.Fatalf("revoked families = %#v, want family-123", tokens.revokedFamilies)
	}
	if len(devices.removed) != 1 || devices.removed[0] != "family-123" {
		t.Fatalf("removed = %#v, want family-123", devices.removed)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "logout_device" || audit.entries[0].Success == nil || !*audit.entries[0].Success {
		t.Fatalf("audit entries = %#v, want successful logout_device", audit.entries)
	}
}

func TestLogoutDeviceRejectsDeviceNotOwned(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	devices := &fakeDevices{owned: false}
	service = withDevices(service, devices)
	tokens := service.Tokens.(*fakeTokens)
	_, err := service.LogoutDevice(context.Background(), LogoutDeviceInput{UserID: 42, DeviceID: "someone-elses"})
	assertKind(t, err, KindNotFound, errcode.CodeNotFound)
	if len(tokens.revokedFamilies) != 0 {
		t.Fatalf("revoked families = %#v, want none revoked for an unowned device", tokens.revokedFamilies)
	}
}

func TestLogoutDeviceFailsClosedWhenStoreUnavailable(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	devices := &fakeDevices{ownedErr: errors.New("redis down")}
	service = withDevices(service, devices)
	tokens := service.Tokens.(*fakeTokens)
	_, err := service.LogoutDevice(context.Background(), LogoutDeviceInput{UserID: 42, DeviceID: "family-123"})
	assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	if len(tokens.revokedFamilies) != 0 {
		t.Fatalf("revoked families = %#v, want no revoke without ownership proof", tokens.revokedFamilies)
	}
}

func TestLogoutDeviceRejectsEmptyDeviceID(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	_, err := service.LogoutDevice(context.Background(), LogoutDeviceInput{UserID: 42, DeviceID: "  "})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

func TestLogoutDeviceThrottlesPerUser(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	service.DeviceLimiter = &fakeLimiter{result: LimitResult{Allowed: false, RetryAfter: time.Minute}}
	devices := &fakeDevices{owned: true}
	service = withDevices(service, devices)
	_, err := service.LogoutDevice(context.Background(), LogoutDeviceInput{UserID: 42, DeviceID: "family-123"})
	assertKind(t, err, KindRateLimited, errcode.CodeRateLimited)
	limiter := service.DeviceLimiter.(*fakeLimiter)
	if got := limiter.calls[0]; got != "device:user:42" {
		t.Fatalf("limiter subject = %q, want per-user key", got)
	}
	if len(devices.removed) != 0 {
		t.Fatal("throttled logout must not touch the device store")
	}
}

func TestLogoutDeviceUnavailableWhenStoreNotConfigured(t *testing.T) {
	service, _, _, _, _, _ := newTestService(t)
	_, err := service.LogoutDevice(context.Background(), LogoutDeviceInput{UserID: 42, DeviceID: "family-123"})
	assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
}
