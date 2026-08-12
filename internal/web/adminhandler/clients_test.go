package adminhandler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminclient"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
)

type fakeClients struct {
	listResult         []adminclient.Client
	listErr            error
	createResult       *adminclient.CreateClientResult
	createErr          error
	createInput        adminclient.CreateClientInput
	updateResult       *adminclient.UpdateClientResult
	updateErr          error
	updateInput        adminclient.UpdateClientInput
	updateCalls        int
	rotateSecretResult *adminclient.RotateClientSecretResult
	rotateSecretErr    error
	rotateSecretInput  adminclient.RotateClientSecretInput
	deleteResult       *adminclient.DeleteClientResult
	deleteErr          error
	deleteInput        adminclient.DeleteClientInput
	deleteCalls        int
}

func (f *fakeClients) RotateClientSecret(
	_ context.Context,
	input adminclient.RotateClientSecretInput,
) (*adminclient.RotateClientSecretResult, error) {
	f.rotateSecretInput = input
	if f.rotateSecretErr != nil {
		return nil, f.rotateSecretErr
	}
	if f.rotateSecretResult == nil {
		return &adminclient.RotateClientSecretResult{ClientSecret: "rotated-secret"}, nil
	}
	return f.rotateSecretResult, nil
}

func (f *fakeClients) ListClients(_ context.Context) ([]adminclient.Client, error) {
	return f.listResult, f.listErr
}

func (f *fakeClients) CreateClient(
	_ context.Context,
	input adminclient.CreateClientInput,
) (*adminclient.CreateClientResult, error) {
	f.createInput = input
	if f.createErr != nil {
		return nil, f.createErr
	}
	return f.createResult, nil
}

func (f *fakeClients) UpdateClient(
	_ context.Context,
	input adminclient.UpdateClientInput,
) (*adminclient.UpdateClientResult, error) {
	f.updateCalls++
	f.updateInput = input
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	if f.updateResult == nil {
		return &adminclient.UpdateClientResult{}, nil
	}
	return f.updateResult, nil
}

func (f *fakeClients) DeleteClient(
	_ context.Context,
	input adminclient.DeleteClientInput,
) (*adminclient.DeleteClientResult, error) {
	f.deleteCalls++
	f.deleteInput = input
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	if f.deleteResult == nil {
		return &adminclient.DeleteClientResult{}, nil
	}
	return f.deleteResult, nil
}

type envelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// newRouter mounts the admin routes with a stub authentication step that injects a
// principal, standing in for RequireAuth + RequireRole.
func newRouter(t *testing.T, service ClientService) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	injectPrincipal := func(c *gin.Context) {
		middleware.SetPrincipal(c, middleware.Principal{UserID: 99, Role: "admin", JTI: "jti-99"})
		c.Next()
	}
	RegisterRoutes(r, Handler{Clients: service}, testGates(injectPrincipal))
	return r
}

// testGates mounts the routes with the given authentication step and passthrough
// scope and role gates. Those gates are covered in middleware and cmd/api; here the
// caller is simply present and permitted, so the handlers are what is under test.
func testGates(requireAuth gin.HandlerFunc) Gates {
	allow := func(c *gin.Context) { c.Next() }
	return Gates{
		RequireAuth: requireAuth, RequireReadScope: allow, RequireWriteScope: allow,
		RequireAdmin: allow, RequireReader: allow,
	}
}

func doRequest(t *testing.T, router *gin.Engine, method, path, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequestWithContext(context.Background(), method, path, reader)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func decodeEnvelope(t *testing.T, recorder *httptest.ResponseRecorder) envelope {
	t.Helper()
	var body envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
	return body
}

func sampleClient() adminclient.Client {
	return adminclient.Client{
		ID: 1, ClientID: "abc123", ClientName: "Evento", ClientType: "third_party",
		RedirectURIs: []string{"https://evento.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile"},
		IsActive:     true,
		CreatedAt:    time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
	}
}

// The list response must never carry secret material. The service DTO has no hash
// field, and this asserts the wire shape stays that way.
func TestListClientsResponseCarriesNoSecretMaterial(t *testing.T) {
	service := &fakeClients{listResult: []adminclient.Client{sampleClient()}}
	router := newRouter(t, service)

	recorder := doRequest(t, router, http.MethodGet, "/admin/oauth-clients", "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	raw := recorder.Body.String()
	for _, forbidden := range []string{"client_secret", "secret", "hash", "sha256"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("list response %q contains %q", raw, forbidden)
		}
	}
	var payload struct {
		Clients []clientDTO `json:"clients"`
	}
	if err := json.Unmarshal(decodeEnvelope(t, recorder).Data, &payload); err != nil {
		t.Fatalf("decode data: %v", err)
	}
	if len(payload.Clients) != 1 || payload.Clients[0].ClientID != "abc123" {
		t.Fatalf("clients = %+v, want the one registration", payload.Clients)
	}
}

// An empty registry must serialize as [] rather than null, so consumers do not have
// to handle two shapes for "none".
func TestListClientsEmptyIsAnArray(t *testing.T) {
	router := newRouter(t, &fakeClients{})

	recorder := doRequest(t, router, http.MethodGet, "/admin/oauth-clients", "", "")
	if !strings.Contains(recorder.Body.String(), `"clients":[]`) {
		t.Fatalf("body = %s, want an empty array", recorder.Body.String())
	}
}

// The secret is returned exactly once, on the response to the request that created
// it, and only for a confidential client.
func TestCreateClientReturnsSecretOnceForThirdParty(t *testing.T) {
	service := &fakeClients{createResult: &adminclient.CreateClientResult{
		Client: sampleClient(), ClientSecret: "s3cr3t-value",
	}}
	router := newRouter(t, service)

	recorder := doRequest(t, router, http.MethodPost, "/admin/oauth-clients", "application/json",
		`{"client_name":"Evento","client_type":"third_party","redirect_uris":["https://evento.test/cb"],"grant_types":["authorization_code"],"scopes":["openid"]}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body.String())
	}
	var created createdClientDTO
	if err := json.Unmarshal(decodeEnvelope(t, recorder).Data, &created); err != nil {
		t.Fatalf("decode data: %v", err)
	}
	if created.ClientSecret != "s3cr3t-value" {
		t.Fatalf("client_secret = %q, want the generated secret", created.ClientSecret)
	}
	// The authenticated admin, not anything from the body, is what gets audited.
	if service.createInput.AdminUserID != 99 {
		t.Fatalf("AdminUserID = %d, want the authenticated principal", service.createInput.AdminUserID)
	}
	// This is the only response in the service carrying a plaintext secret, so it must
	// not be storable by an intermediary or browser cache.
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store on a response carrying a secret", got)
	}
}

// A public client has no secret, so the field must be absent rather than empty:
// an empty string would suggest a credential exists and is blank.
func TestCreateClientOmitsSecretForFirstParty(t *testing.T) {
	client := sampleClient()
	client.ClientType = "first_party"
	router := newRouter(t, &fakeClients{createResult: &adminclient.CreateClientResult{Client: client}})

	recorder := doRequest(t, router, http.MethodPost, "/admin/oauth-clients", "application/json",
		`{"client_name":"Web","client_type":"first_party","redirect_uris":["https://web.test/cb"],"grant_types":["authorization_code"],"scopes":["openid"]}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "client_secret") {
		t.Fatalf("first_party response %s mentions client_secret", recorder.Body.String())
	}
}

// A request attempting to choose its own client_id, or to set a secret, must be
// refused rather than have the field ignored: silently dropping it would let an
// operator believe they had registered under a chosen identifier.
func TestCreateClientRejectsCallerSuppliedIdentityFields(t *testing.T) {
	for _, body := range []string{
		`{"client_name":"X","client_type":"third_party","redirect_uris":["https://x.test/cb"],"grant_types":["authorization_code"],"scopes":["openid"],"client_id":"sast-link-web"}`,
		`{"client_name":"X","client_type":"third_party","redirect_uris":["https://x.test/cb"],"grant_types":["authorization_code"],"scopes":["openid"],"client_secret":"chosen"}`,
		`{"client_name":"X","client_type":"third_party","redirect_uris":["https://x.test/cb"],"grant_types":["authorization_code"],"scopes":["openid"],"id":5}`,
	} {
		service := &fakeClients{createResult: &adminclient.CreateClientResult{Client: sampleClient()}}
		router := newRouter(t, service)

		recorder := doRequest(t, router, http.MethodPost, "/admin/oauth-clients", "application/json", body)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d for %s, want 400", recorder.Code, body)
		}
		if service.createInput.ClientName != "" {
			t.Fatalf("the service was reached for %s", body)
		}
	}
}

// client_id / client_secret / client_type / id have no field on the update
// request, so an attempt to send one is a 400 from the strict decoder rather than
// a silently ignored edit: choosing your own identifier is refused, never dropped.
// client_type is immutable — flipping it without reissuing a secret would create a
// credential-less third_party client.
func TestUpdateClientRejectsCallerSuppliedIdentityFields(t *testing.T) {
	for _, body := range []string{
		`{"client_id":"sast-link-web"}`,
		`{"client_secret":"chosen"}`,
		`{"client_type":"third_party"}`,
		`{"id":5}`,
	} {
		service := &fakeClients{}
		router := newRouter(t, service)

		recorder := doRequest(t, router, http.MethodPut, "/admin/oauth-clients/5", "application/json", body)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d for %s, want 400", recorder.Code, body)
		}
		if service.updateCalls != 0 {
			t.Fatalf("the service was reached for %s", body)
		}
	}
}

// The consent-relevant contract fields are editable: grant_types and scopes.
// Validation happens in the service; here the handler must forward the submitted
// pointers untouched.
func TestUpdateClientForwardsEditableContractFields(t *testing.T) {
	service := &fakeClients{}
	router := newRouter(t, service)

	recorder := doRequest(t, router, http.MethodPut, "/admin/oauth-clients/5", "application/json",
		`{"grant_types":["authorization_code","refresh_token"],"scopes":["openid","profile"]}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if service.updateInput.GrantTypes == nil || len(*service.updateInput.GrantTypes) != 2 {
		t.Fatalf("GrantTypes = %v, want two entries", service.updateInput.GrantTypes)
	}
	if service.updateInput.Scope == nil || len(*service.updateInput.Scope) != 2 {
		t.Fatalf("Scope = %v, want two entries", service.updateInput.Scope)
	}
}

// An omitted field must be left alone, not cleared.
func TestUpdateClientForwardsOnlySubmittedFields(t *testing.T) {
	service := &fakeClients{}
	router := newRouter(t, service)

	recorder := doRequest(t, router, http.MethodPut, "/admin/oauth-clients/5", "application/json",
		`{"client_name":"Renamed"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if service.updateInput.ClientName == nil || *service.updateInput.ClientName != "Renamed" {
		t.Fatalf("ClientName = %v, want Renamed", service.updateInput.ClientName)
	}
	if service.updateInput.RedirectURIs != nil || service.updateInput.IsActive != nil {
		t.Fatal("omitted fields were forwarded as present")
	}
}

// is_active:false must arrive as an explicit false, not be lost as a zero value.
func TestUpdateClientForwardsExplicitFalse(t *testing.T) {
	service := &fakeClients{updateResult: &adminclient.UpdateClientResult{RevokedTokens: 3}}
	router := newRouter(t, service)

	recorder := doRequest(t, router, http.MethodPut, "/admin/oauth-clients/5", "application/json",
		`{"is_active":false}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if service.updateInput.IsActive == nil || *service.updateInput.IsActive {
		t.Fatalf("IsActive = %v, want an explicit false", service.updateInput.IsActive)
	}
	// Revoking sessions is a bigger consequence than "updated", so the message says so.
	body := decodeEnvelope(t, recorder)
	var payload messageResponse
	if err := json.Unmarshal(body.Data, &payload); err != nil {
		t.Fatalf("decode data: %v", err)
	}
	if !strings.Contains(payload.Message, "撤销") {
		t.Fatalf("data message = %q, want it to mention revocation", payload.Message)
	}
}

// A non-numeric or non-positive ID names no client, so it gets the same 404 as a
// missing one rather than a 400 that distinguishes the two.
func TestUpdateClientRejectsBadPathID(t *testing.T) {
	for _, id := range []string{"abc", "0", "-1", "1.5", "%20"} {
		service := &fakeClients{}
		router := newRouter(t, service)

		recorder := doRequest(t, router, http.MethodPut, "/admin/oauth-clients/"+id,
			"application/json", `{"client_name":"X"}`)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("status = %d for id %q, want 404", recorder.Code, id)
		}
		if service.updateCalls != 0 {
			t.Fatalf("the service was reached for id %q", id)
		}
	}
}

func TestServiceErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   int
	}{
		{"invalid input", &adminclient.Error{
			Kind: adminclient.KindInvalidInput, Code: errcode.CodeBadRequest,
			Message: "redirect_uri 仅允许 https，http 限 localhost",
		}, http.StatusBadRequest, errcode.CodeBadRequest},
		{"not found", &adminclient.Error{
			Kind: adminclient.KindNotFound, Code: errcode.CodeClientNotFound,
		}, http.StatusNotFound, errcode.CodeClientNotFound},
		{"internal", &adminclient.Error{
			Kind: adminclient.KindInternal, Code: errcode.CodeInternal,
		}, http.StatusInternalServerError, errcode.CodeInternal},
		{"untyped", errors.New("boom"), http.StatusInternalServerError, errcode.CodeInternal},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			router := newRouter(t, &fakeClients{listErr: test.err})

			recorder := doRequest(t, router, http.MethodGet, "/admin/oauth-clients", "", "")
			body := decodeEnvelope(t, recorder)
			if recorder.Code != test.wantStatus || body.Code != test.wantCode {
				t.Fatalf("response = %d/%d, want %d/%d", recorder.Code, body.Code, test.wantStatus, test.wantCode)
			}
		})
	}
}

// An internal failure must not leak the underlying cause; the validation message,
// which is a literal naming the broken rule, is what should reach the caller.
func TestErrorBodiesDoNotLeakCauses(t *testing.T) {
	router := newRouter(t, &fakeClients{listErr: &adminclient.Error{
		Kind: adminclient.KindInternal, Code: errcode.CodeInternal,
		Message: "查询 OAuth 客户端失败", Err: errors.New("pq: password authentication failed for user postgres"),
	}})

	recorder := doRequest(t, router, http.MethodGet, "/admin/oauth-clients", "", "")
	if strings.Contains(recorder.Body.String(), "postgres") ||
		strings.Contains(recorder.Body.String(), "password") {
		t.Fatalf("error body leaked the cause: %s", recorder.Body.String())
	}
}

// Without a Principal the handler cannot attribute the action, which means the
// middleware chain is wired wrong: a 500, not a silent write with no audit subject.
func TestCreateClientWithoutPrincipalIsAnInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeClients{createResult: &adminclient.CreateClientResult{Client: sampleClient()}}
	r := gin.New()
	allow := func(c *gin.Context) { c.Next() }
	RegisterRoutes(r, Handler{Clients: service}, testGates(allow))

	recorder := doRequest(t, r, http.MethodPost, "/admin/oauth-clients", "application/json",
		`{"client_name":"X","client_type":"third_party","redirect_uris":["https://x.test/cb"],"grant_types":["authorization_code"],"scopes":["openid"]}`)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	if service.createInput.ClientName != "" {
		t.Fatal("the service was reached without an authenticated admin")
	}
}

func TestRejectsWrongContentTypeAndOversizedBody(t *testing.T) {
	t.Run("wrong content type", func(t *testing.T) {
		service := &fakeClients{}
		router := newRouter(t, service)
		recorder := doRequest(t, router, http.MethodPut, "/admin/oauth-clients/5",
			"text/plain", `{"client_name":"X"}`)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", recorder.Code)
		}
	})
	t.Run("oversized body", func(t *testing.T) {
		service := &fakeClients{}
		router := newRouter(t, service)
		body := `{"client_name":"` + strings.Repeat("a", 128<<10) + `"}`
		recorder := doRequest(t, router, http.MethodPut, "/admin/oauth-clients/5",
			"application/json", body)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", recorder.Code)
		}
		if service.updateCalls != 0 {
			t.Fatal("an oversized body reached the service")
		}
	})
}

// The rotate-secret response carries the new plaintext exactly once and is
// no-store, mirroring the registration response. The path id and the
// authenticated principal are what reach the service.
func TestRotateClientSecretReturnsSecretOnce(t *testing.T) {
	service := &fakeClients{rotateSecretResult: &adminclient.RotateClientSecretResult{ClientSecret: "rotated-secret-value"}}
	router := newRouter(t, service)

	recorder := doRequest(t, router, http.MethodPost, "/admin/oauth-clients/1/rotate-secret", "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		ID           int64  `json:"id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(decodeEnvelope(t, recorder).Data, &payload); err != nil {
		t.Fatalf("decode data: %v", err)
	}
	if payload.ClientSecret != "rotated-secret-value" {
		t.Fatalf("client_secret = %q, want the rotated secret", payload.ClientSecret)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store on a response carrying a secret", got)
	}
	if service.rotateSecretInput.ClientPK != 1 || service.rotateSecretInput.AdminUserID != 99 {
		t.Fatalf("rotate input = %+v, want the path id and authenticated principal", service.rotateSecretInput)
	}
}

// Deleting a registration reaches the service with the path id and the
// authenticated principal, and returns an ok envelope rather than a body the
// frontend has to read.
func TestDeleteClientRemovesRegistration(t *testing.T) {
	service := &fakeClients{}
	router := newRouter(t, service)

	recorder := doRequest(t, router, http.MethodDelete, "/admin/oauth-clients/5", "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	payload := decodeEnvelope(t, recorder)
	if payload.Code != 0 {
		t.Fatalf("envelope code = %d, want 0", payload.Code)
	}
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(payload.Data, &body); err != nil {
		t.Fatalf("decode data: %v", err)
	}
	if body.Message != "客户端已删除" {
		t.Fatalf("message = %q, want %q (no revocation happened)", body.Message, "客户端已删除")
	}
	if service.deleteCalls != 1 {
		t.Fatalf("DeleteClient called %d times, want 1", service.deleteCalls)
	}
	if service.deleteInput.ClientPK != 5 || service.deleteInput.AdminUserID != 99 {
		t.Fatalf("delete input = %+v, want the path id and authenticated principal", service.deleteInput)
	}
}

// A deletion that cut live sessions is worth calling out in the message, the same
// way the update handler does when disabling a client revokes tokens.
func TestDeleteClientReportsRevokedTokens(t *testing.T) {
	service := &fakeClients{deleteResult: &adminclient.DeleteClientResult{RevokedTokens: 3}}
	router := newRouter(t, service)

	recorder := doRequest(t, router, http.MethodDelete, "/admin/oauth-clients/5", "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(decodeEnvelope(t, recorder).Data, &payload); err != nil {
		t.Fatalf("decode data: %v", err)
	}
	if !strings.Contains(payload.Message, "已撤销") {
		t.Fatalf("message = %q, want it to mention the revoked tokens", payload.Message)
	}
}

// A non-numeric or non-positive path segment names no client and gets the same
// 404 as a missing one, without reaching the service.
func TestDeleteClientRejectsBadPathID(t *testing.T) {
	service := &fakeClients{}
	router := newRouter(t, service)

	recorder := doRequest(t, router, http.MethodDelete, "/admin/oauth-clients/not-a-number", "", "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	if service.deleteCalls != 0 {
		t.Fatalf("DeleteClient called %d times on a bad path id, want 0", service.deleteCalls)
	}
}
