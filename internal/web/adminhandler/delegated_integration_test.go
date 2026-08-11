package adminhandler_test

// End-to-end coverage for delegated administration against a real PostgreSQL and
// Redis, through real HTTP requests and the real middleware chain.
//
// This is the one file that exercises the gates themselves. Every other admin test
// mounts passthrough stubs in their place, which proves the handlers work but says
// nothing about whether an actual third-party token reaches them — and that question
// is the entire point of the feature. The tokens here are genuinely signed and their
// access rows genuinely persisted, so the azp gate, the scope gate and the role gate
// all run exactly as production runs them.
//
// It deliberately does not drive /oauth/authorize: that leg needs a browser. What it
// covers instead is everything after the token exists, which is where the new
// authorization decisions live.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	oauthredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/oauth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/migration"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminclient"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminuser"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/adminhandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
)

const (
	delegatedE2EInternalClientID = "sast-link-web"
	delegatedE2ESessionClientID  = "delegated-e2e-session"
	// delegatedE2EDelegatedClientID is a fixture client this test registers itself,
	// holding the admin scopes. Nothing in the middleware knows this name — a token
	// reaches /admin by carrying an admin scope, which only a registration granted one
	// can produce — so this constant names a fixture, not a rule.
	delegatedE2EDelegatedClientID = "delegated-e2e-admin"
)

type delegatedHarness struct {
	router   *gin.Engine
	database *gorm.DB
	jwt      *auth.JWTManager
	tokens   *repository.TokenRepository
	admin    *model.User
	member   *model.User
	clientPK int64
}

// setupDelegated mounts the admin routes behind the production gates, wired the same
// way cmd/api wires them.
func setupDelegated(t *testing.T) *delegatedHarness {
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
	store := internalredis.Store{
		Client: testutil.StartRedis(t),
		Keys:   internalredis.NewKeys("sastlink:delegated-e2e"),
	}

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	jwtManager := &auth.JWTManager{
		Issuer:   adminE2EIssuer,
		Audience: []string{"sast-link-v2"},
		Active:   auth.JWTKeyPair{KID: "delegated-e2e", Private: key},
	}

	users := repository.NewUser(database)
	admin := adminE2EUser("delegated-admin@njupt.edu.cn", "B24040401", model.UserRoleAdmin)
	if err := users.CreateWithProfile(context.Background(), admin, &model.Profile{}); err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	member := adminE2EUser("delegated-member@njupt.edu.cn", "B24040402", model.UserRoleMember)
	if err := users.CreateWithProfile(context.Background(), member, &model.Profile{}); err != nil {
		t.Fatalf("create member user: %v", err)
	}

	tokens := repository.NewToken(database)
	auditLog := repository.NewAuditLog(database)
	blacklist := oauthredis.BlacklistStore{Store: store}

	// The delegated client is registered by this fixture rather than seeded by a
	// migration: delegation is a console grant, so there is no schema-level delegate to
	// read back. Its primary key is what the access-token rows have to reference.
	delegatedSecret := auth.HashClientSecret("delegated-e2e-secret")
	delegatedActive := true
	delegatedClient := &model.OAuthClient{
		ClientID:   delegatedE2EDelegatedClientID,
		ClientName: "Delegated E2E Admin",
		ClientType: model.ClientTypeThirdParty,
		// Confidential, the shape checkCapabilityScopeGrant requires of anything
		// holding an admin scope.
		ClientSecretHash: &delegatedSecret,
		RedirectURIs:     model.StringArray{"https://delegated-e2e.test/cb"},
		GrantTypes:       model.StringArray{"authorization_code"},
		Scopes:           model.StringArray{scope.OpenID, scope.AdminRead, scope.AdminWrite},
		IsActive:         &delegatedActive,
	}
	if err := database.Create(delegatedClient).Error; err != nil {
		t.Fatalf("register delegated client: %v", err)
	}

	// No client is named here. The authenticator admits a token on the strength of
	// its admin scope alone, so this wiring is what production uses for every
	// capability client rather than for one blessed client_id.
	authenticator := middleware.Authenticator{
		JWT:              jwtManager,
		Tokens:           tokens,
		InternalClientID: delegatedE2EInternalClientID,
	}

	router := gin.New()
	adminhandler.RegisterRoutes(router, adminhandler.Handler{
		Clients: adminclient.Service{
			Clients: repository.NewOAuthClient(database), Blacklist: blacklist,
			Audit: auditLog, Secrets: auth.ClientSecretHasher{},
			ProtectedClientID: delegatedE2EInternalClientID,
		},
		Users: adminuser.Service{
			Users: users, Audit: auditLog, Blacklist: blacklist,
			ConsoleClientID: delegatedE2EInternalClientID,
		},
		AuditLogs: adminuser.Service{
			Users: users, Audit: auditLog, Blacklist: blacklist,
			ConsoleClientID: delegatedE2EInternalClientID,
		},
	}, adminhandler.Gates{
		RequireAuth:       authenticator.RequireAdminAuth(),
		RequireReadScope:  authenticator.RequireDelegatedScope(adminhandler.ReadScopes...),
		RequireWriteScope: authenticator.RequireDelegatedScope(adminhandler.WriteScopes...),
		RequireAdmin:      authenticator.RequireRole(adminhandler.AdminRole),
		RequireReader:     authenticator.RequireRole(adminhandler.ReaderRoles...),
	})

	return &delegatedHarness{
		router: router, database: database, jwt: jwtManager, tokens: tokens,
		admin: admin, member: member, clientPK: delegatedClient.ID,
	}
}

// issueToken signs an access token for the given client and scopes and persists the
// row the middleware reads, so revocation and expiry state are real.
func (h *delegatedHarness) issueToken(
	t *testing.T, user *model.User, clientID string, scopes []string,
) string {
	t.Helper()
	jti := "jti-" + clientID + "-" + strconv.FormatInt(user.ID, 10) + "-" +
		strconv.Itoa(len(scopes))
	token, err := h.jwt.SignAccessToken(auth.TokenInput{
		Subject:         strconv.FormatInt(user.ID, 10),
		JTI:             jti,
		Role:            string(user.Role),
		State:           string(user.State),
		TokenVersion:    user.TokenVersion,
		Scopes:          scopes,
		TTL:             time.Hour,
		AuthorizedParty: clientID,
	})
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}
	// The access row is created through CreatePair, which is the only way rows land in
	// production: the two tables are written together so a family always has both halves.
	// The refresh half is inert here — nothing in this file redeems it.
	expiresAt := time.Now().Add(time.Hour).UTC()
	// Both halves must name the same family: the repository rejects a mismatch, because
	// a family is what cascade revocation operates on.
	familyID := uuid.NewString()
	if err := h.tokens.CreatePair(context.Background(),
		&model.OAuthAccessToken{
			TokenID:   jti,
			ClientID:  h.clientPK,
			UserID:    user.ID,
			FamilyID:  &familyID,
			Scopes:    model.StringArray(scopes),
			ExpiresAt: expiresAt,
		},
		&model.OAuthRefreshToken{
			TokenHash: "hash-" + jti,
			FamilyID:  familyID,
			Sequence:  0,
			ClientID:  h.clientPK,
			UserID:    user.ID,
			Scopes:    model.StringArray(scopes),
			ExpiresAt: expiresAt,
		},
	); err != nil {
		t.Fatalf("persist token pair: %v", err)
	}
	return token
}

func (h *delegatedHarness) request(t *testing.T, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	var request *http.Request
	if reader != nil {
		request = httptest.NewRequestWithContext(context.Background(), method, path, reader)
		request.Header.Set("Content-Type", "application/json")
	} else {
		request = httptest.NewRequestWithContext(context.Background(), method, path, nil)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, request)
	return recorder
}

// The full authorization matrix, driven through real HTTP with real tokens. Each row
// is a claim about production behavior that no unit test can make: the gates are the
// composition root's, not stubs.
func TestDelegatedAdminAccessMatrix(t *testing.T) {
	testutil.RequireProvider(t)
	h := setupDelegated(t)
	memberPath := "/admin/users/" + strconv.FormatInt(h.member.ID, 10)

	adminReadToken := h.issueToken(t, h.admin, delegatedE2EDelegatedClientID,
		[]string{scope.OpenID, scope.AdminRead})
	adminWriteToken := h.issueToken(t, h.admin, delegatedE2EDelegatedClientID,
		[]string{scope.OpenID, scope.AdminRead, scope.AdminWrite})
	noScopeToken := h.issueToken(t, h.admin, delegatedE2EDelegatedClientID,
		[]string{scope.OpenID})
	sessionToken := h.issueToken(t, h.admin, delegatedE2ESessionClientID,
		[]string{scope.OpenID, scope.Profile, scope.Email})
	consoleToken := h.issueToken(t, h.admin, delegatedE2EInternalClientID,
		[]string{scope.OpenID, scope.Profile, scope.Email})
	demotedToken := h.issueToken(t, h.member, delegatedE2EDelegatedClientID,
		[]string{scope.OpenID, scope.AdminRead, scope.AdminWrite})
	// A client_id no migration ever seeded and no constant names. This is the feature's
	// actual claim: an operator onboards a second ops tool through the console, and its
	// tokens work without a code change.
	otherDelegateToken := h.issueToken(t, h.admin, "some-other-ops-tool",
		[]string{scope.OpenID, scope.AdminRead, scope.AdminWrite})

	for _, test := range []struct {
		name       string
		token      string
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{
			name: "admin:read reaches a read route", token: adminReadToken,
			method: http.MethodGet, path: "/admin/users", wantStatus: http.StatusOK,
		},
		{
			// The scope gate must stop this before the handler mutates anything.
			name: "admin:read cannot write", token: adminReadToken,
			method: http.MethodPut, path: memberPath, body: `{"name":"改名"}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "admin:write reaches a write route", token: adminWriteToken,
			method: http.MethodPut, path: memberPath, body: `{"name":"改名"}`,
			wantStatus: http.StatusOK,
		},
		{
			// Rejected by RequireAdminAuth, before any scope check: a delegated client
			// without an admin scope is not acting as a delegate at all.
			name: "delegated client without an admin scope is refused", token: noScopeToken,
			method: http.MethodGet, path: "/admin/users", wantStatus: http.StatusForbidden,
		},
		{
			// The session client is not the delegate, however ordinary its scopes.
			name: "session client cannot reach the admin surface", token: sessionToken,
			method: http.MethodGet, path: "/admin/users", wantStatus: http.StatusForbidden,
		},
		{
			// The console holds only session scopes and must stay exempt from the scope gate.
			name: "console token reaches a read route", token: consoleToken,
			method: http.MethodGet, path: "/admin/users", wantStatus: http.StatusOK,
		},
		{
			name: "console token reaches a write route", token: consoleToken,
			method: http.MethodPut, path: memberPath, body: `{"name":"控制台改名"}`,
			wantStatus: http.StatusOK,
		},
		{
			// The role ceiling is the user's, not the client's: a member's token carrying
			// admin:write is still only a member. The role gate reads the database row.
			name: "admin scopes do not lift a non-admin user", token: demotedToken,
			method: http.MethodGet, path: "/admin/audit-logs", wantStatus: http.StatusForbidden,
		},
		{
			// An unnamed delegate reaches the surface on its scope alone.
			name: "any client holding admin:write reaches a write route", token: otherDelegateToken,
			method: http.MethodPut, path: memberPath, body: `{"name":"第二个工具改名"}`,
			wantStatus: http.StatusOK,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := h.request(t, test.method, test.path, test.token, test.body)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s",
					recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if test.wantStatus == http.StatusForbidden {
				var envelope struct {
					Code int `json:"code"`
				}
				if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
					t.Fatalf("decode error envelope: %v", err)
				}
				if envelope.Code != errcode.CodeForbidden {
					t.Fatalf("business code = %d, want %d", envelope.Code, errcode.CodeForbidden)
				}
			}
		})
	}
}

// The audit trail must name the acting credential, which is the whole reason
// actor_client_id exists: a delegated write and a console write are the same
// administrator, and only this column separates them.
func TestDelegatedAdminWriteRecordsActorClientID(t *testing.T) {
	testutil.RequireProvider(t)
	h := setupDelegated(t)
	memberPath := "/admin/users/" + strconv.FormatInt(h.member.ID, 10)

	delegated := h.issueToken(t, h.admin, delegatedE2EDelegatedClientID,
		[]string{scope.OpenID, scope.AdminRead, scope.AdminWrite})
	if recorder := h.request(t, http.MethodPut, memberPath, delegated,
		`{"name":"工具改名"}`); recorder.Code != http.StatusOK {
		t.Fatalf("delegated write status = %d, want 200; body = %s",
			recorder.Code, recorder.Body.String())
	}

	console := h.issueToken(t, h.admin, delegatedE2EInternalClientID,
		[]string{scope.OpenID, scope.Profile, scope.Email})
	if recorder := h.request(t, http.MethodPut, memberPath, console,
		`{"name":"控制台改名"}`); recorder.Code != http.StatusOK {
		t.Fatalf("console write status = %d, want 200; body = %s",
			recorder.Code, recorder.Body.String())
	}

	// The audit write is detached (context.WithoutCancel plus a timeout), so it may
	// land just after the response. Poll rather than sleep a fixed interval.
	var actors []string
	for range 50 {
		actors = actors[:0]
		var rows []model.AuditLog
		if err := h.database.Where("action = ?", "admin_user_update").
			Order("id ASC").Find(&rows).Error; err != nil {
			t.Fatalf("read audit rows: %v", err)
		}
		for _, row := range rows {
			if row.ActorClientID != nil {
				actors = append(actors, *row.ActorClientID)
			}
		}
		if len(actors) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if len(actors) != 2 {
		t.Fatalf("audit actors = %v, want two rows naming their client", actors)
	}
	if actors[0] != delegatedE2EDelegatedClientID {
		t.Fatalf("delegated write actor = %q, want %q", actors[0], delegatedE2EDelegatedClientID)
	}
	// The console records the built-in client explicitly rather than NULL, which is what
	// keeps NULL meaning "no OAuth credential authorized this".
	if actors[1] != delegatedE2EInternalClientID {
		t.Fatalf("console write actor = %q, want %q", actors[1], delegatedE2EInternalClientID)
	}
}
