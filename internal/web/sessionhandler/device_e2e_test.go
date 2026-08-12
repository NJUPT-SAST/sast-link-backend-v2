package sessionhandler_test

// End-to-end coverage of device management against a real PostgreSQL and Redis:
// password login registers a device keyed by the token family, the device list
// reflects it, and logging a device out revokes its whole token family so its
// refresh token dies while other devices keep working.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	sessionredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/migration"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/sessionhandler"
)

type deviceE2EHarness struct {
	router  *gin.Engine
	service session.Service
	userID  int64
}

func setupDeviceE2E(t *testing.T) *deviceE2EHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)

	databaseURL := testutil.StartPostgres(t)
	instance, err := migration.New(databaseURL)
	if err != nil {
		t.Fatalf("create migration: %v", err)
	}
	t.Cleanup(func() { _, _ = instance.Close() })
	if migrateErr := instance.Up(); migrateErr != nil {
		t.Fatalf("apply migrations: %v", migrateErr)
	}
	database := testutil.OpenGORM(t, databaseURL)
	rdb := testutil.StartRedis(t)
	store := internalredis.Store{Client: rdb, Keys: internalredis.NewKeys("sastlink:test")}

	users := repository.NewUser(database)
	clients := repository.NewOAuthClient(database)
	tokens := repository.NewToken(database)
	audit := repository.NewAuditLog(database)

	// A real user with a real password hash, so the login path is exercised
	// end to end.
	passwords := auth.PasswordHasher{}
	hash, err := passwords.HashPassword(context.Background(), "secret-pass")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		Name:         "设备端到端",
		PhoneNumber:  "13800130042",
		QQNumber:     "10042",
		PasswordHash: hash,
		LoginEmail:   "device-e2e@njupt.edu.cn",
		StudentID:    "B2404042",
		Role:         model.UserRoleMember,
		State:        model.UserStateOnSAST,
		EmailType:    model.EmailTypeNJUpt,
		College:      model.CollegeOther,
	}
	if createErr := users.CreateWithProfile(context.Background(), user, &model.Profile{}); createErr != nil {
		t.Fatalf("create user: %v", createErr)
	}

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	clock := auth.SystemClock
	service := session.Service{
		Users:            users,
		Clients:          clients,
		Tokens:           tokens,
		Audit:            audit,
		Limiter:          sessionredis.EndpointLimiter{Limiter: internalredis.FixedWindowLimiter{Client: rdb, Keys: store.Keys, Limit: 100, Window: time.Minute}},
		Failures:         sessionredis.LoginFailureStore{Store: store, Limit: 10, Window: 15 * time.Minute},
		Blacklist:        sessionredis.BlacklistStore{Store: store},
		Devices:          sessionredis.DeviceStore{Store: store},
		DeviceLimiter:    sessionredis.EndpointLimiter{Limiter: internalredis.FixedWindowLimiter{Client: rdb, Keys: store.Keys, Limit: 100, Window: time.Minute}},
		InternalClientID: "sast-link-web",
		JWT:              &auth.JWTManager{Issuer: "issuer", Audience: []string{"audience"}, Active: auth.JWTKeyPair{KID: "active", Private: key}, Clock: clock},
		RefreshTokens:    &auth.RefreshTokenManager{Random: rand.Reader, Secret: []byte("0123456789abcdef0123456789abcdef")},
		Passwords:        passwords,
		Clock:            clock,
		AccessTTL:        time.Hour,
		RefreshTTL:       24 * time.Hour,
	}

	router := gin.New()
	sessionhandler.RegisterRoutes(router, sessionhandler.Handler{Service: service}, sessionhandler.Gates{
		RequireAuth: func(c *gin.Context) {
			middleware.SetPrincipal(c, middleware.Principal{UserID: user.ID, JTI: "device-e2e", ExpiresAt: time.Now().Add(time.Hour)})
			c.Next()
		},
		RequireReadScope:  func(c *gin.Context) { c.Next() },
		RequireWriteScope: func(c *gin.Context) { c.Next() },
	})
	return &deviceE2EHarness{router: router, service: service, userID: user.ID}
}

func (h *deviceE2EHarness) listDevices(t *testing.T) []map[string]any {
	t.Helper()
	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/user/devices", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /user/devices status = %d, body: %s", recorder.Code, recorder.Body.String())
	}
	devices := decodeE2EList(t, recorder)
	return devices
}

func decodeE2EList(t *testing.T, recorder *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	// Reuse the same envelope decoding the handler tests use, without importing
	// the internal test helpers: decode the raw body here.
	// The envelope is {"code":0,"message":"ok","data":{"devices":[...]}}.
	// This test only needs the device ids, so a minimal decode suffices.
	type envelope struct {
		Code int `json:"code"`
		Data struct {
			Devices []map[string]any `json:"devices"`
		} `json:"data"`
	}
	var body envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode list: %v; body=%s", err, recorder.Body.String())
	}
	if body.Code != 0 {
		t.Fatalf("list code = %d, body=%s", body.Code, recorder.Body.String())
	}
	return body.Data.Devices
}

// The per-user cap is enforced at the session level, not just in the device
// list: logging in a sixth device evicts the oldest record and revokes its
// whole token family, so the displaced session cannot keep refreshing.
func TestDeviceE2EEvictionRevokesOldestFamily(t *testing.T) {
	harness := setupDeviceE2E(t)
	ctx := context.Background()

	logins := make([]*session.LoginResult, 0, 6)
	for i := 0; i < 6; i++ {
		result, err := harness.service.Login(ctx, session.LoginInput{
			Identifier: "device-e2e@njupt.edu.cn",
			Password:   "secret-pass",
			ClientIP:   "10.0.0." + string(rune('1'+i)),
			UserAgent:  "device/" + string(rune('1'+i)),
		})
		if err != nil {
			t.Fatalf("login %d: %v", i+1, err)
		}
		logins = append(logins, result)
	}

	// The list caps at 5; the sixth login evicted the first device.
	devices := harness.listDevices(t)
	if len(devices) != 5 {
		t.Fatalf("devices = %#v, want 5 after six logins", devices)
	}

	// The evicted device's refresh token must be dead.
	if _, err := harness.service.Refresh(ctx, session.RefreshInput{RefreshToken: logins[0].RefreshToken}); err == nil {
		t.Fatal("refresh with the evicted device's token succeeded, want rejection")
	}
	// The newest device's session keeps working.
	rotated, err := harness.service.Refresh(ctx, session.RefreshInput{RefreshToken: logins[5].RefreshToken})
	if err != nil {
		t.Fatalf("refresh with the newest device's token failed: %v", err)
	}
	if rotated.AccessToken == "" {
		t.Fatal("newest refresh produced no access token")
	}
}

func TestDeviceE2ELogoutRevokesFamilyAndKeepsOthers(t *testing.T) {
	harness := setupDeviceE2E(t)
	ctx := context.Background()

	// Device 1 logs in with a browser.
	first, err := harness.service.Login(ctx, session.LoginInput{Identifier: "device-e2e@njupt.edu.cn", Password: "secret-pass", ClientIP: "10.0.0.1", UserAgent: "browser/1"})
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	// Device 2 logs in with an app.
	second, err := harness.service.Login(ctx, session.LoginInput{Identifier: "device-e2e@njupt.edu.cn", Password: "secret-pass", ClientIP: "10.0.0.2", UserAgent: "app/2"})
	if err != nil {
		t.Fatalf("second login: %v", err)
	}

	devices := harness.listDevices(t)
	if len(devices) != 2 {
		t.Fatalf("devices = %#v, want 2 after two logins", devices)
	}
	// Newest (device 2) first, with request metadata captured.
	if devices[0]["ua"] != "app/2" || devices[0]["ip"] != "10.0.0.2" {
		t.Fatalf("first device meta = %#v, want app/2 from 10.0.0.2", devices[0])
	}
	if devices[1]["ua"] != "browser/1" {
		t.Fatalf("second device meta = %#v, want browser/1", devices[1])
	}

	// Log out device 1 through the HTTP endpoint.
	deviceID := devices[1]["device_id"].(string)
	survivorID := devices[0]["device_id"].(string)
	recorder := httptest.NewRecorder()
	harness.router.ServeHTTP(recorder, httptest.NewRequestWithContext(ctx, http.MethodDelete, "/user/devices/"+deviceID, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("DELETE /user/devices status = %d, body: %s", recorder.Code, recorder.Body.String())
	}

	// The revoked family's refresh token must be dead…
	if _, refreshErr := harness.service.Refresh(ctx, session.RefreshInput{RefreshToken: first.RefreshToken}); refreshErr == nil {
		t.Fatal("refresh with the logged-out device's token succeeded, want rejection")
	}
	// …while the other device's session keeps working.
	rotated, err := harness.service.Refresh(ctx, session.RefreshInput{RefreshToken: second.RefreshToken})
	if err != nil {
		t.Fatalf("refresh with the surviving device's token failed: %v", err)
	}
	if rotated.AccessToken == "" {
		t.Fatal("surviving refresh produced no access token")
	}

	devices = harness.listDevices(t)
	if len(devices) != 1 {
		t.Fatalf("devices after logout = %#v, want exactly the surviving device", devices)
	}
	if devices[0]["device_id"] != survivorID || devices[0]["device_id"] == deviceID {
		t.Fatalf("surviving device = %#v, want %q (not the logged-out %q)", devices[0], survivorID, deviceID)
	}
}
