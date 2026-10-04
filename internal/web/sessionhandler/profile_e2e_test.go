package sessionhandler_test

// End-to-end coverage of the department role gate on PUT /user/profile
// against a real PostgreSQL. The auth middleware is stubbed with a principal
// carrying an explicit role — the value principalFromClaims produces from the
// live database row — because the point here is the wiring from that role
// through the handler into the service gate and down to the profile row.

import (
	"context"
	"fmt"
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
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/sessionhandler"
)

type profileE2EHarness struct {
	router   *gin.Engine
	database *gorm.DB
	userID   int64
}

func setupProfileE2E(t *testing.T, role model.UserRole) *profileE2EHarness {
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
		Name:         "部门端到端",
		PhoneNumber:  "13800130043",
		QQNumber:     "10043",
		PasswordHash: "password-hash",
		LoginEmail:   "department-e2e@njupt.edu.cn",
		StudentID:    "B2404043",
		Role:         role,
		State:        model.UserStateOnSAST,
		EmailType:    model.EmailTypeNJUpt,
		College:      model.CollegeOther,
	}
	if err := users.CreateWithProfile(context.Background(), user, &model.Profile{}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	service := session.Service{
		Users: users,
		Audit: repository.NewAuditLog(database),
	}
	router := gin.New()
	sessionhandler.RegisterRoutes(router, sessionhandler.Handler{Service: service}, sessionhandler.Gates{
		RequireAuth: func(c *gin.Context) {
			middleware.SetPrincipal(c, middleware.Principal{
				UserID: user.ID, JTI: "department-e2e", Role: string(role),
				ExpiresAt: time.Now().Add(time.Hour),
			})
			c.Next()
		},
		RequireReadScope:  func(c *gin.Context) { c.Next() },
		RequireWriteScope: func(c *gin.Context) { c.Next() },
		RequireLogoutAuth: func(c *gin.Context) { c.Next() },
	})
	return &profileE2EHarness{router: router, database: database, userID: user.ID}
}

func (h *profileE2EHarness) putProfile(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/user/profile", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	h.router.ServeHTTP(recorder, request)
	return recorder
}

func (h *profileE2EHarness) department(t *testing.T) *string {
	t.Helper()
	var profile model.Profile
	if err := h.database.Where("user_id = ?", h.userID).First(&profile).Error; err != nil {
		t.Fatalf("load profile: %v", err)
	}
	return (*string)(profile.Department)
}

// A member submitting department is refused the way a permission field the
// path does not expose would be, and the refusal leaves the column untouched.
func TestProfileE2EMemberCannotEditDepartment(t *testing.T) {
	harness := setupProfileE2E(t, model.UserRoleMember)
	recorder := harness.putProfile(t, `{"department":"software"}`)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", recorder.Code, recorder.Body.String())
	}
	if want := fmt.Sprintf(`"code":%d`, errcode.CodeBadRequest); !strings.Contains(recorder.Body.String(), want) {
		t.Fatalf("body = %s, want business code %d", recorder.Body.String(), errcode.CodeBadRequest)
	}
	if department := harness.department(t); department != nil {
		t.Fatalf("department = %q, want untouched nil", *department)
	}
}

// The same request under a manager principal lands in the profile row.
func TestProfileE2EManagerEditsOwnDepartment(t *testing.T) {
	harness := setupProfileE2E(t, model.UserRoleManager)
	recorder := harness.putProfile(t, `{"department":"software"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	if department := harness.department(t); department == nil || *department != "software" {
		t.Fatalf("department = %v, want software", department)
	}
}

// The gate covers only the department key: a member keeps every other
// self-service edit.
func TestProfileE2EMemberEditsOtherFields(t *testing.T) {
	harness := setupProfileE2E(t, model.UserRoleMember)
	recorder := harness.putProfile(t, `{"intro":"新介绍"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	if department := harness.department(t); department != nil {
		t.Fatalf("department = %q, want nil", *department)
	}
}
