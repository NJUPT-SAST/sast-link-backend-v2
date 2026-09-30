package provider

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

const testTenantKey = "sast-tenant"

func larkTestClient(doer Doer, tenantKey string) *LarkClient {
	return NewLark(LarkConfig{
		AppID:       "cli_app",
		AppSecret:   "app-secret",
		RedirectURI: "https://link.sast.fun/v2/oauth/lark/callback",
		TenantKey:   tenantKey,
	}, doer, fixedClock())
}

// larkHappyResponses is the three-call sequence a successful Lark exchange makes:
// app_access_token, then the user token, then user_info.
func larkHappyResponses(tenantKey string) map[string]fakeResponse {
	return map[string]fakeResponse{
		larkAppAccessTokenURL: {status: http.StatusOK, body: `{
			"code":0,"msg":"ok","app_access_token":"a-token","expire":7200}`},
		larkUserTokenURL: {status: http.StatusOK, body: `{
			"code":0,"access_token":"u-token","refresh_token":"r-token",
			"expires_in":7200,"token_type":"Bearer"}`},
		larkUserInfoURL: {status: http.StatusOK, body: `{
			"code":0,"msg":"success","data":{
				"name":"张三","en_name":"San Zhang",
				"avatar_url":"https://lark.example/avatar.png",
				"open_id":"ou_open","union_id":"on_union","user_id":"u123",
				"email":"zhangsan@sast.fun","mobile":"+8613800138000",
				"tenant_key":"` + tenantKey + `"}}`},
	}
}

func TestLarkAuthorizeURLCarriesAppIDAndState(t *testing.T) {
	got := larkTestClient(&fakeDoer{}, testTenantKey).AuthorizeURL("state-xyz")
	if !strings.HasPrefix(got, larkAuthorizeURL+"?") {
		t.Fatalf("authorize URL = %q, want the Lark authorize endpoint", got)
	}
	for _, want := range []string{"app_id=cli_app", "state=state-xyz"} {
		if !strings.Contains(got, want) {
			t.Fatalf("authorize URL %q is missing %q", got, want)
		}
	}
}

func TestLarkExchangeUsesUnionIDAsProviderID(t *testing.T) {
	doer := &fakeDoer{responses: larkHappyResponses(testTenantKey)}
	identity, err := larkTestClient(doer, testTenantKey).Exchange(context.Background(), "code-1", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	// union_id is stable across every app in the tenant; open_id varies per app
	// and would break the binding once a second app is registered.
	if identity.ProviderID != "on_union" {
		t.Fatalf("ProviderID = %q, want the union_id \"on_union\"", identity.ProviderID)
	}
	if identity.Data["open_id"] != "ou_open" {
		t.Fatalf("identity_data open_id = %v, want \"ou_open\"", identity.Data["open_id"])
	}
	if identity.Data["union_id"] != "on_union" {
		t.Fatalf("identity_data union_id = %v, want \"on_union\"", identity.Data["union_id"])
	}
	if identity.DisplayName != "张三" {
		t.Fatalf("DisplayName = %q, want \"张三\"", identity.DisplayName)
	}
	// identity_data is read by admin tooling; the flow never uses these, so
	// they must not be persisted.
	for _, leaked := range []string{"mobile", "email", "enterprise_email"} {
		if _, ok := identity.Data[leaked]; ok {
			t.Fatalf("identity_data carries PII field %q", leaked)
		}
	}

	tokenReq := doer.requestFor(t, larkUserTokenURL)
	if tokenReq.header.Get("Authorization") != "Bearer a-token" {
		t.Fatalf("token request Authorization = %q, want the app_access_token",
			tokenReq.header.Get("Authorization"))
	}
	userReq := doer.requestFor(t, larkUserInfoURL)
	if userReq.header.Get("Authorization") != "Bearer u-token" {
		t.Fatalf("user_info Authorization = %q, want the user access token",
			userReq.header.Get("Authorization"))
	}
}

func TestLarkExchangeRejectsForeignTenant(t *testing.T) {
	doer := &fakeDoer{responses: larkHappyResponses("other-company")}
	_, err := larkTestClient(doer, testTenantKey).Exchange(context.Background(), "code-1", "")
	if !errors.Is(err, ErrForeignTenant) {
		t.Fatalf("error = %v, want ErrForeignTenant", err)
	}
}

func TestLarkExchangeAllowsAnyTenantWhenGateDisabled(t *testing.T) {
	// An empty TenantKey disables the gate. Only tests should rely on this.
	doer := &fakeDoer{responses: larkHappyResponses("other-company")}
	identity, err := larkTestClient(doer, "").Exchange(context.Background(), "code-1", "")
	if err != nil {
		t.Fatalf("Exchange with the gate disabled: %v", err)
	}
	if identity.ProviderID != "on_union" {
		t.Fatalf("ProviderID = %q", identity.ProviderID)
	}
}

func TestLarkExchangeRejectsMissingUnionID(t *testing.T) {
	responses := larkHappyResponses(testTenantKey)
	responses[larkUserInfoURL] = fakeResponse{status: http.StatusOK, body: `{
		"code":0,"data":{"name":"张三","open_id":"ou_open","tenant_key":"` + testTenantKey + `"}}`}
	doer := &fakeDoer{responses: responses}

	// Falling back to open_id here would create a binding that silently breaks
	// when a second Lark app is registered, so this must fail loudly.
	_, err := larkTestClient(doer, testTenantKey).Exchange(context.Background(), "code-1", "")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("error = %v, want ErrUnexpectedResponse", err)
	}
}

func TestLarkExchangeMapsClientRejectionToInvalidGrant(t *testing.T) {
	// The v2 token endpoint reports a spent code with a 4xx status rather than
	// a body field. That must read as invalid_grant, not a provider outage.
	responses := larkHappyResponses(testTenantKey)
	responses[larkUserTokenURL] = fakeResponse{
		status: http.StatusBadRequest,
		body:   `{"code":20037,"error":"invalid_grant","error_description":"code is expired"}`,
	}
	doer := &fakeDoer{responses: responses}
	_, err := larkTestClient(doer, testTenantKey).Exchange(context.Background(), "spent", "")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("error = %v, want ErrInvalidGrant", err)
	}
}

func TestLarkExchangeKeepsServerErrorAsOutage(t *testing.T) {
	responses := larkHappyResponses(testTenantKey)
	responses[larkUserTokenURL] = fakeResponse{status: http.StatusBadGateway, body: `gateway down`}
	doer := &fakeDoer{responses: responses}

	_, err := larkTestClient(doer, testTenantKey).Exchange(context.Background(), "code-1", "")
	if errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("error = %v, want an outage rather than ErrInvalidGrant", err)
	}
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("error = %v, want ErrUnexpectedResponse", err)
	}
}

func TestLarkExchangeRejectsAppTokenApplicationError(t *testing.T) {
	// Lark signals application errors with HTTP 200 plus a non-zero code, so the
	// body's code field has to be checked even on success.
	responses := larkHappyResponses(testTenantKey)
	responses[larkAppAccessTokenURL] = fakeResponse{
		status: http.StatusOK,
		body:   `{"code":10003,"msg":"invalid app_secret"}`,
	}
	doer := &fakeDoer{responses: responses}

	_, err := larkTestClient(doer, testTenantKey).Exchange(context.Background(), "code-1", "")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("error = %v, want ErrUnexpectedResponse", err)
	}
	// A bad app credential is not the user's fault; mapping it to invalid_grant
	// would tell the user their login expired when the deployment is misconfigured.
	if errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("error = %v, must not be ErrInvalidGrant", err)
	}
}

func TestLarkExchangeRejectsUserInfoApplicationError(t *testing.T) {
	responses := larkHappyResponses(testTenantKey)
	responses[larkUserInfoURL] = fakeResponse{
		status: http.StatusOK,
		body:   `{"code":99991663,"msg":"token invalid"}`,
	}
	doer := &fakeDoer{responses: responses}

	_, err := larkTestClient(doer, testTenantKey).Exchange(context.Background(), "code-1", "")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("error = %v, want ErrUnexpectedResponse", err)
	}
}

func TestLarkExchangeFallsBackToEnName(t *testing.T) {
	responses := larkHappyResponses(testTenantKey)
	responses[larkUserInfoURL] = fakeResponse{status: http.StatusOK, body: `{
		"code":0,"data":{"name":"","en_name":"San Zhang","union_id":"on_union",
		"tenant_key":"` + testTenantKey + `"}}`}
	doer := &fakeDoer{responses: responses}

	identity, err := larkTestClient(doer, testTenantKey).Exchange(context.Background(), "code-1", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.DisplayName != "San Zhang" {
		t.Fatalf("DisplayName = %q, want the en_name fallback", identity.DisplayName)
	}
}

// larkAppCodeHappyResponses is the three-call sequence a successful
// login-free exchange makes: app_access_token, the v1 OIDC token endpoint,
// then user_info. It differs from larkHappyResponses only at the token step.
func larkAppCodeHappyResponses(tenantKey string) map[string]fakeResponse {
	responses := larkHappyResponses(tenantKey)
	delete(responses, larkUserTokenURL)
	responses[larkOIDCTokenURL] = fakeResponse{status: http.StatusOK, body: `{
		"code":0,"msg":"success","data":{
			"access_token":"u-token","refresh_token":"r-token","token_type":"Bearer",
			"expires_in":7200,"refresh_expires_in":2591999,
			"scope":"auth:user.id:read"}}`}
	return responses
}

func TestLarkExchangeAppCodeUsesUnionIDAsProviderID(t *testing.T) {
	doer := &fakeDoer{responses: larkAppCodeHappyResponses(testTenantKey)}
	identity, err := larkTestClient(doer, testTenantKey).ExchangeAppCode(context.Background(), "code-app")
	if err != nil {
		t.Fatalf("ExchangeAppCode: %v", err)
	}
	if identity.ProviderID != "on_union" {
		t.Fatalf("ProviderID = %q, want the union_id \"on_union\"", identity.ProviderID)
	}
	if identity.AccessToken != "u-token" || identity.RefreshToken != "r-token" {
		t.Fatalf("tokens = %q/%q, want u-token/r-token", identity.AccessToken, identity.RefreshToken)
	}
	if identity.TokenExpiresAt == nil {
		t.Fatal("TokenExpiresAt is nil, want it derived from expires_in")
	}

	// The OIDC endpoint authenticates the app through the app_access_token and
	// must not see a redirect_uri or client_secret: the code never rode a
	// redirect, and repeating the secret next to the header adds a second way
	// to misconfigure the app for no benefit.
	tokenReq := doer.requestFor(t, larkOIDCTokenURL)
	if tokenReq.header.Get("Authorization") != "Bearer a-token" {
		t.Fatalf("oidc request Authorization = %q, want the app_access_token",
			tokenReq.header.Get("Authorization"))
	}
	for _, forbidden := range []string{"redirect_uri", "client_secret"} {
		if strings.Contains(tokenReq.body, forbidden) {
			t.Fatalf("oidc request body %q carries %q", tokenReq.body, forbidden)
		}
	}
	if !strings.Contains(tokenReq.body, `"code":"code-app"`) {
		t.Fatalf("oidc request body %q is missing the code", tokenReq.body)
	}
	userReq := doer.requestFor(t, larkUserInfoURL)
	if userReq.header.Get("Authorization") != "Bearer u-token" {
		t.Fatalf("user_info Authorization = %q, want the user access token",
			userReq.header.Get("Authorization"))
	}
}

func TestLarkExchangeAppCodeRejectsForeignTenant(t *testing.T) {
	doer := &fakeDoer{responses: larkAppCodeHappyResponses("other-company")}

	_, err := larkTestClient(doer, testTenantKey).ExchangeAppCode(context.Background(), "code-app")
	if !errors.Is(err, ErrForeignTenant) {
		t.Fatalf("error = %v, want ErrForeignTenant", err)
	}
}

func TestLarkExchangeAppCodeRejectsMissingUnionID(t *testing.T) {
	responses := larkAppCodeHappyResponses(testTenantKey)
	responses[larkUserInfoURL] = fakeResponse{status: http.StatusOK, body: `{
		"code":0,"data":{"name":"张三","tenant_key":"` + testTenantKey + `"}}`}
	doer := &fakeDoer{responses: responses}

	_, err := larkTestClient(doer, testTenantKey).ExchangeAppCode(context.Background(), "code-app")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("error = %v, want ErrUnexpectedResponse", err)
	}
}

func TestLarkExchangeAppCodeMapsSpentOrExpiredCodeToInvalidGrant(t *testing.T) {
	for _, code := range []int{20003, 20004} {
		responses := larkAppCodeHappyResponses(testTenantKey)
		responses[larkOIDCTokenURL] = fakeResponse{status: http.StatusOK, body: `{
			"code":` + strconv.Itoa(code) + `,"msg":"the code is invalid"}`}
		doer := &fakeDoer{responses: responses}

		_, err := larkTestClient(doer, testTenantKey).ExchangeAppCode(context.Background(), "code-app")
		if !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("code %d: error = %v, want ErrInvalidGrant", code, err)
		}
	}
}

func TestLarkExchangeAppCodeKeepsOtherApplicationErrorAsOutage(t *testing.T) {
	// 20014 is an invalid app_access_token: an app-side fault, not something
	// the caller can fix by presenting a fresh pre-authorization code.
	responses := larkAppCodeHappyResponses(testTenantKey)
	responses[larkOIDCTokenURL] = fakeResponse{status: http.StatusOK, body: `{
		"code":20014,"msg":"invalid app access token"}`}
	doer := &fakeDoer{responses: responses}

	_, err := larkTestClient(doer, testTenantKey).ExchangeAppCode(context.Background(), "code-app")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("error = %v, want ErrUnexpectedResponse", err)
	}
}

func TestLarkExchangeAppCodeReusesCachedAppToken(t *testing.T) {
	doer := &fakeDoer{responses: larkAppCodeHappyResponses(testTenantKey)}
	client := larkTestClient(doer, testTenantKey)

	for i := 0; i < 2; i++ {
		if _, err := client.ExchangeAppCode(context.Background(), "code-app"); err != nil {
			t.Fatalf("ExchangeAppCode #%d: %v", i, err)
		}
	}
	appTokenCalls := 0
	for _, req := range doer.requests {
		if strings.HasPrefix(req.url, larkAppAccessTokenURL) {
			appTokenCalls++
		}
	}
	if appTokenCalls != 1 {
		t.Fatalf("app_access_token fetched %d times, want the 2h cache to serve both exchanges",
			appTokenCalls)
	}
}
