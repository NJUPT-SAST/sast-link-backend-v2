package sessionhandler_test

// End-to-end coverage of PUT /user/avatar against a real PostgreSQL and Redis,
// through real HTTP requests. The object store and the content review are fakes:
// the point of this file is the wiring — multipart parsing, service use case,
// profile write, audit row — not the COS adapter, which has no disposable
// counterpart.

import (
	"bytes"
	"context"
	"image"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/migration"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/objectstore"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/sessionhandler"
)

// e2eAvatarStore is the in-memory stand-in for the COS adapter.
type e2eAvatarStore struct {
	objects map[string][]byte
	deleted []string
}

func (s *e2eAvatarStore) Upload(_ context.Context, key string, r io.Reader, _ string, _ int64) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	s.objects[key] = data
	return "https://cdn.e2e.test/" + key, nil
}

func (s *e2eAvatarStore) Delete(_ context.Context, key string) error {
	s.deleted = append(s.deleted, key)
	delete(s.objects, key)
	return nil
}

type e2eAvatarAuditor struct {
	result objectstore.AuditResult
	err    error
}

func (a *e2eAvatarAuditor) AuditImage(_ context.Context, _ string) (objectstore.AuditResult, error) {
	return a.result, a.err
}

type avatarE2EHarness struct {
	router   *gin.Engine
	database *gorm.DB
	userID   int64
	store    *e2eAvatarStore
}

func setupAvatarE2E(t *testing.T) *avatarE2EHarness {
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

	users := repository.NewUser(database)
	user := &model.User{
		Name:         "头像端到端",
		PhoneNumber:  "13800130042",
		QQNumber:     "10042",
		PasswordHash: "password-hash",
		LoginEmail:   "avatar-e2e@njupt.edu.cn",
		StudentID:    "B2404042",
		Role:         model.UserRoleMember,
		State:        model.UserStateOnSAST,
		EmailType:    model.EmailTypeNJUpt,
		College:      model.CollegeOther,
	}
	if err := users.CreateWithProfile(context.Background(), user, &model.Profile{}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	objects := &e2eAvatarStore{objects: map[string][]byte{}}
	service := session.Service{
		Users:         users,
		Audit:         repository.NewAuditLog(database),
		AvatarStore:   objects,
		AvatarAuditor: &e2eAvatarAuditor{result: objectstore.AuditResult{Sensitive: false, Label: "Normal"}},
	}
	router := gin.New()
	sessionhandler.RegisterRoutes(router, sessionhandler.Handler{Service: service}, sessionhandler.Gates{
		RequireAuth: func(c *gin.Context) {
			middleware.SetPrincipal(c, middleware.Principal{UserID: user.ID, JTI: "avatar-e2e", ExpiresAt: time.Now().Add(time.Hour)})
			c.Next()
		},
		RequireReadScope:  func(c *gin.Context) { c.Next() },
		RequireWriteScope: func(c *gin.Context) { c.Next() },
	})
	return &avatarE2EHarness{router: router, database: database, userID: user.ID, store: objects}
}

func avatarE2EUploadRequest(t *testing.T, content []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "avatar.png")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write form part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/user/avatar", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func avatarE2EPNG(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 4, 4))); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

// The full path: multipart in, object stored, profile.avatar persisted, audit
// row written — all against real PostgreSQL.
func TestAvatarE2EUploadPersistsProfileAndAudit(t *testing.T) {
	harness := setupAvatarE2E(t)
	recorder := httptest.NewRecorder()
	harness.router.ServeHTTP(recorder, avatarE2EUploadRequest(t, avatarE2EPNG(t)))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	if len(harness.store.objects) != 1 {
		t.Fatalf("stored objects = %d, want 1", len(harness.store.objects))
	}
	var key string
	for k := range harness.store.objects {
		key = k
	}
	if !strings.HasPrefix(key, "avatar/") || !strings.Contains(key, ".png") {
		t.Fatalf("object key = %q, want avatar/<id>/<uuid>.png", key)
	}

	var profile model.Profile
	if err := harness.database.Where("user_id = ?", harness.userID).First(&profile).Error; err != nil {
		t.Fatalf("load profile: %v", err)
	}
	if profile.Avatar == nil || *profile.Avatar != "https://cdn.e2e.test/"+key {
		t.Fatalf("profile.avatar = %v, want %q", profile.Avatar, "https://cdn.e2e.test/"+key)
	}

	var audit model.AuditLog
	if err := harness.database.Where("action = ? AND user_id = ?", "upload_avatar", harness.userID).First(&audit).Error; err != nil {
		t.Fatalf("load audit row: %v", err)
	}
	if audit.Success == nil || !*audit.Success {
		t.Fatalf("audit success = %v, want true", audit.Success)
	}
	if !strings.Contains(string(audit.Detail), *profile.Avatar) {
		t.Fatalf("audit detail = %s, want avatar_url", audit.Detail)
	}
}

// A rejected review must fail the request, leave profile.avatar untouched and
// remove the stored object (fail-closed cleanup).
func TestAvatarE2ERejectsSensitiveContent(t *testing.T) {
	harness := setupAvatarE2E(t)
	harness.router = avatarE2ERouterWithAuditor(t, harness, &e2eAvatarAuditor{
		result: objectstore.AuditResult{Sensitive: true, Label: "Porn"},
	})
	recorder := httptest.NewRecorder()
	harness.router.ServeHTTP(recorder, avatarE2EUploadRequest(t, avatarE2EPNG(t)))

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", recorder.Code)
	}
	if len(harness.store.objects) != 0 {
		t.Fatalf("stored objects = %d, want 0 after rejection", len(harness.store.objects))
	}
	var profile model.Profile
	if err := harness.database.Where("user_id = ?", harness.userID).First(&profile).Error; err != nil {
		t.Fatalf("load profile: %v", err)
	}
	if profile.Avatar != nil {
		t.Fatalf("profile.avatar = %v, want nil after rejection", *profile.Avatar)
	}
	var audit model.AuditLog
	if err := harness.database.Where("action = ? AND user_id = ?", "upload_avatar", harness.userID).First(&audit).Error; err != nil {
		t.Fatalf("load audit row: %v", err)
	}
	if audit.Success != nil && *audit.Success {
		t.Fatal("audit success = true, want false for rejected review")
	}
	if audit.ErrCode == nil || *audit.ErrCode != errcode.CodeAvatarRejected {
		t.Fatalf("audit err_code = %v, want 42203", audit.ErrCode)
	}
}

func avatarE2ERouterWithAuditor(t *testing.T, harness *avatarE2EHarness, auditor objectstore.AvatarAuditor) *gin.Engine {
	t.Helper()
	users := repository.NewUser(harness.database)
	service := session.Service{
		Users:         users,
		Audit:         repository.NewAuditLog(harness.database),
		AvatarStore:   harness.store,
		AvatarAuditor: auditor,
	}
	router := gin.New()
	sessionhandler.RegisterRoutes(router, sessionhandler.Handler{Service: service}, sessionhandler.Gates{
		RequireAuth: func(c *gin.Context) {
			middleware.SetPrincipal(c, middleware.Principal{UserID: harness.userID, JTI: "avatar-e2e", ExpiresAt: time.Now().Add(time.Hour)})
			c.Next()
		},
		RequireReadScope:  func(c *gin.Context) { c.Next() },
		RequireWriteScope: func(c *gin.Context) { c.Next() },
	})
	return router
}
