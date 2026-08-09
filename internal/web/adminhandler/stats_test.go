package adminhandler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminclient"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminuser"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
)

// statsEnvelope captures the /admin/stats response shape for assertions.
type statsEnvelope struct {
	Users   repository.UserStats `json:"users"`
	Clients statsClientSummary   `json:"clients"`
	Audit   struct {
		Recent []json.RawMessage `json:"recent"`
	} `json:"audit"`
}

// newStatsRouter mounts the admin routes with a stub authentication step, standing
// in for RequireAuth plus the admin role gate on GET /admin/stats.
func newStatsRouter(t *testing.T, users UserService, clients ClientService, auditLogs AuditLogService) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	injectPrincipal := func(c *gin.Context) {
		middleware.SetPrincipal(c, middleware.Principal{UserID: 99, Role: "admin", JTI: "jti-99"})
		c.Next()
	}
	allow := func(c *gin.Context) { c.Next() }
	RegisterRoutes(r, Handler{Users: users, Clients: clients, AuditLogs: auditLogs}, injectPrincipal, allow, allow)
	return r
}

func decodeStats(t *testing.T, recorder *httptest.ResponseRecorder) statsEnvelope {
	t.Helper()
	var payload statsEnvelope
	if err := json.Unmarshal(decodeEnvelope(t, recorder).Data, &payload); err != nil {
		t.Fatalf("decode data: %v", err)
	}
	return payload
}

func TestStatsReturnsAllAggregates(t *testing.T) {
	users := &fakeUsers{statsResult: repository.UserStats{Total: 1450}}
	clients := &fakeClients{listResult: []adminclient.Client{sampleClient()}}
	audit := &fakeAuditLogs{result: &adminuser.ListAuditLogsResult{Logs: []adminuser.AuditLogItem{{ID: 1}}}}
	router := newStatsRouter(t, users, clients, audit)

	recorder := doRequest(t, router, http.MethodGet, "/admin/stats", "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	payload := decodeStats(t, recorder)
	if payload.Users.Total != 1450 {
		t.Fatalf("users.total = %d, want 1450", payload.Users.Total)
	}
	if payload.Clients.Total != 1 || payload.Clients.Active != 1 {
		t.Fatalf("clients = %d/%d, want 1 active of 1", payload.Clients.Total, payload.Clients.Active)
	}
	if len(payload.Audit.Recent) != 1 {
		t.Fatalf("audit.recent = %d entries, want 1", len(payload.Audit.Recent))
	}
}

// A failed audit-trail read is tolerated by design, but must read as an empty
// list, never as a 500 and never as a JSON null — the overview cannot silently
// lose its other two legs over a best-effort field.
func TestStatsAuditFailureFallsOpenWithEmptyArray(t *testing.T) {
	users := &fakeUsers{statsResult: repository.UserStats{Total: 3}}
	clients := &fakeClients{listResult: []adminclient.Client{sampleClient()}}
	audit := &fakeAuditLogs{err: errors.New("audit query failed")}
	router := newStatsRouter(t, users, clients, audit)

	recorder := doRequest(t, router, http.MethodGet, "/admin/stats", "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"recent":[]`) {
		t.Fatalf("body = %s, want recent to serialize as an empty array", recorder.Body.String())
	}
	payload := decodeStats(t, recorder)
	if payload.Users.Total != 3 || payload.Clients.Total != 1 {
		t.Fatalf("users/clients = %d/%d, want the healthy legs intact on audit failure",
			payload.Users.Total, payload.Clients.Total)
	}
}

// users and clients are the authoritative legs: losing either must surface as a
// 500, not as zeroed aggregates that read as "no data".
func TestStatsUserOrClientFailureIs500(t *testing.T) {
	for _, test := range []struct {
		name    string
		users   *fakeUsers
		clients *fakeClients
	}{
		{
			name:    "user stats failure",
			users:   &fakeUsers{statsErr: errors.New("count users failed")},
			clients: &fakeClients{},
		},
		{
			name:    "client list failure",
			users:   &fakeUsers{},
			clients: &fakeClients{listErr: errors.New("list clients failed")},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := newStatsRouter(t, test.users, test.clients, &fakeAuditLogs{})
			recorder := doRequest(t, router, http.MethodGet, "/admin/stats", "", "")
			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

// Clients and AuditLogs are optional dependencies; nil must degrade to zeroed
// aggregates rather than panic, matching the endpoint's documented tolerance.
func TestStatsDegradesWhenOptionalDependenciesNil(t *testing.T) {
	users := &fakeUsers{statsResult: repository.UserStats{Total: 5}}
	router := newStatsRouter(t, users, nil, nil)

	recorder := doRequest(t, router, http.MethodGet, "/admin/stats", "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	payload := decodeStats(t, recorder)
	if payload.Users.Total != 5 || payload.Clients.Total != 0 || len(payload.Audit.Recent) != 0 {
		t.Fatalf("users/clients/recent = %d/%d/%d, want 5/0/0",
			payload.Users.Total, payload.Clients.Total, len(payload.Audit.Recent))
	}
}
