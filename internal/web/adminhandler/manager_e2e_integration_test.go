package adminhandler_test

// End-to-end coverage for the manager boundary against a real PostgreSQL, over
// the real service and repository stack: a manager provisions and manages
// member accounts — promoting to manager included, self-replication being the
// point of the role — but neither touches an admin's account nor grants the
// admin role. The accounts it provisions derive like student accounts, and the
// phone field rides along on every read surface, exactly as it does for an
// admin.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/migration"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminuser"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/adminhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
)

// managerE2EHarness mounts the admin console with a manager principal over a
// real migrated PostgreSQL. The role gates themselves are pinned by cmd/api's
// route tests; here every gate allows and the principal is a manager, so what
// is under test is the service-layer boundary that the gates alone cannot
// express.
type managerE2EHarness struct {
	router   *gin.Engine
	database *gorm.DB
	manager  *model.User
}

func setupManagerE2E(t *testing.T) *managerE2EHarness {
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
	auditLog := repository.NewAuditLog(database)
	manager := adminE2EUser("manager-e2e@njupt.edu.cn", "B24040311", model.UserRoleManager)
	if err := users.CreateWithProfile(context.Background(), manager, &model.Profile{}); err != nil {
		t.Fatalf("create manager user: %v", err)
	}
	admin := adminE2EUser("admin-e2e-target@njupt.edu.cn", "B24040312", model.UserRoleAdmin)
	if err := users.CreateWithProfile(context.Background(), admin, &model.Profile{}); err != nil {
		t.Fatalf("create admin target user: %v", err)
	}

	service := adminuser.Service{Users: users, Audit: auditLog}
	allow := func(c *gin.Context) { c.Next() }
	router := gin.New()
	adminhandler.RegisterRoutes(router, adminhandler.Handler{Users: service, AuditLogs: service}, adminhandler.Gates{
		RequireAuth: func(c *gin.Context) {
			middleware.SetPrincipal(c, middleware.Principal{
				UserID: manager.ID, Role: string(model.UserRoleManager), JTI: "manager-e2e",
			})
			c.Next()
		},
		RequireReadScope:  allow,
		RequireWriteScope: allow,
		RequireAdmin:      allow,
		RequireReader:     allow,
		RequireUserWriter: allow,
	})
	return &managerE2EHarness{router: router, database: database, manager: manager}
}

func (h *managerE2EHarness) do(t *testing.T, method, target, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	var request *http.Request
	if body == "" {
		request = httptest.NewRequestWithContext(context.Background(), method, target, nil)
	} else {
		request = httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, request)
	return recorder
}

func TestManagerE2EBoundary(t *testing.T) {
	testutil.RequireProvider(t)
	h := setupManagerE2E(t)

	// The member the boundary is exercised against, created by the manager
	// itself — the ordinary recruitment path.
	created := h.do(t, http.MethodPost, "/admin/users", "application/json",
		`{"name":"测试成员","student_id":"B24040321","login_email":"b24040321@njupt.edu.cn",
		  "phone_number":"13900139001","qq_number":"24040321","major":"软件工程"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create status = %d: %s", created.Code, created.Body.String())
	}
	var createdBody struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil {
		t.Fatalf("decode create body: %v", err)
	}
	memberTarget := strconv.FormatInt(createdBody.Data.ID, 10)

	t.Run("sees the phone field and derives njupter", func(t *testing.T) {
		detail := h.do(t, http.MethodGet, "/admin/users/"+memberTarget, "", "")
		if detail.Code != http.StatusOK {
			t.Fatalf("detail status = %d: %s", detail.Code, detail.Body.String())
		}
		if !strings.Contains(detail.Body.String(), `"phone_number":"13900139001"`) {
			t.Fatalf("manager detail missing phone_number: %s", detail.Body.String())
		}
		// A 2024-cohort account derives to njupter whatever its role: the
		// completion follow-up buckets cover managers like the members they manage.
		var state string
		if err := h.database.Model(&model.User{}).Where("id = ?", createdBody.Data.ID).
			Pluck("state", &state).Error; err != nil || state != string(model.UserStateNJUPTer) {
			t.Fatalf("provisioned state = %q err = %v, want njupter", state, err)
		}
	})

	t.Run("promotes a member to manager (self-replication)", func(t *testing.T) {
		promoted := h.do(t, http.MethodPut, "/admin/users", "application/json",
			`{"ids":[`+memberTarget+`],"role":"manager"}`)
		if promoted.Code != http.StatusOK {
			t.Fatalf("batch promote status = %d: %s", promoted.Code, promoted.Body.String())
		}
		if !strings.Contains(promoted.Body.String(), `"success":true`) {
			t.Fatalf("batch promote item failed: %s", promoted.Body.String())
		}
	})

	t.Run("cannot grant the admin role", func(t *testing.T) {
		refused := h.do(t, http.MethodPut, "/admin/users", "application/json",
			`{"ids":[`+memberTarget+`],"role":"admin"}`)
		if refused.Code != http.StatusOK {
			t.Fatalf("batch status = %d: %s", refused.Code, refused.Body.String())
		}
		// Per-item refusal, not a transport failure.
		if !strings.Contains(refused.Body.String(), "不可授予 admin 角色") {
			t.Fatalf("missing admin-grant refusal: %s", refused.Body.String())
		}
		var role string
		if err := h.database.Model(&model.User{}).Where("id = ?", createdBody.Data.ID).
			Pluck("role", &role).Error; err != nil || role != string(model.UserRoleManager) {
			t.Fatalf("role after refused grant = %q err = %v, want manager", role, err)
		}
	})

	t.Run("cannot provision an admin directly", func(t *testing.T) {
		refused := h.do(t, http.MethodPost, "/admin/users", "application/json",
			`{"name":"越权账号","student_id":"B24040331","login_email":"b24040331@njupt.edu.cn",
		  "phone_number":"13900139002","qq_number":"24040331","role":"admin"}`)
		if refused.Code != http.StatusForbidden {
			t.Fatalf("create-admin status = %d, want 403: %s", refused.Code, refused.Body.String())
		}
	})

	t.Run("cannot bind a personal email on an existing account", func(t *testing.T) {
		refused := h.do(t, http.MethodPut, "/admin/users/"+memberTarget, "application/json",
			`{"personal_email":"manager-picked@qq.com"}`)
		if refused.Code != http.StatusForbidden {
			t.Fatalf("bind status = %d, want 403: %s", refused.Code, refused.Body.String())
		}
		if !strings.Contains(refused.Body.String(), "仅管理员可绑定 personal_email") {
			t.Fatalf("missing bind refusal: %s", refused.Body.String())
		}
		var bound int64
		if err := h.database.Model(&model.Identity{}).
			Where("user_id = ? AND provider = ?", createdBody.Data.ID, model.LoginMethodOtherMail).
			Count(&bound).Error; err != nil || bound != 0 {
			t.Fatalf("other_mail bound behind the boundary: count = %d err = %v", bound, err)
		}
	})

	t.Run("cannot provision with a personal email", func(t *testing.T) {
		refused := h.do(t, http.MethodPost, "/admin/users", "application/json",
			`{"name":"直绑账号","student_id":"B24040341","login_email":"b24040341@njupt.edu.cn",
		  "phone_number":"13900139003","qq_number":"24040341","personal_email":"manager-picked@qq.com"}`)
		if refused.Code != http.StatusForbidden {
			t.Fatalf("create-bind status = %d, want 403: %s", refused.Code, refused.Body.String())
		}
		var provisioned int64
		if err := h.database.Model(&model.User{}).
			Where("student_id = ?", "B24040341").
			Count(&provisioned).Error; err != nil || provisioned != 0 {
			t.Fatalf("account created behind the boundary: count = %d err = %v", provisioned, err)
		}
	})

	t.Run("cannot edit or close an admin account", func(t *testing.T) {
		var adminID int64
		if err := h.database.Model(&model.User{}).
			Where("login_email = ?", "admin-e2e-target@njupt.edu.cn").
			Pluck("id", &adminID).Error; err != nil || adminID == 0 {
			t.Fatalf("load admin id: %v", err)
		}
		adminTarget := strconv.FormatInt(adminID, 10)

		edited := h.do(t, http.MethodPut, "/admin/users/"+adminTarget, "application/json", `{"name":"越权改名"}`)
		if edited.Code != http.StatusForbidden {
			t.Fatalf("edit-admin status = %d, want 403: %s", edited.Code, edited.Body.String())
		}
		closed := h.do(t, http.MethodDelete, "/admin/users/"+adminTarget, "", "")
		if closed.Code != http.StatusForbidden {
			t.Fatalf("delete-admin status = %d, want 403: %s", closed.Code, closed.Body.String())
		}
		var count int64
		if err := h.database.Model(&model.User{}).
			Where("id = ? AND state = ?", adminID, model.UserStateDeleted).
			Count(&count).Error; err != nil || count != 0 {
			t.Fatalf("admin closed behind the boundary: count = %d err = %v", count, err)
		}
	})
}
