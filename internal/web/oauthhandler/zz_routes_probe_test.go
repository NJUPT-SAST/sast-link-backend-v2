package oauthhandler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
)

type probeSvc struct{}

func (probeSvc) Authorize(context.Context, oauth.AuthorizeInput) (*oauth.AuthorizeResult, error) {
	return &oauth.AuthorizeResult{RequestID: "ar_x", ClientName: "c", Scopes: []string{"openid"}}, nil
}
func (probeSvc) Consent(context.Context, oauth.ConsentInput) (*oauth.ConsentResult, error) {
	return &oauth.ConsentResult{RedirectURI: "https://rp/cb?code=1"}, nil
}
func (probeSvc) Token(context.Context, oauth.TokenInput) (*oauth.TokenResult, error) {
	return &oauth.TokenResult{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 3600, Scope: "openid"}, nil
}
func (probeSvc) Revoke(context.Context, oauth.RevokeInput) error { return nil }
func (probeSvc) UserInfo(context.Context, oauth.UserInfoInput) (*oauth.UserInfoResult, error) {
	return &oauth.UserInfoResult{Subject: "1"}, nil
}
func (probeSvc) Discovery() map[string]any { return map[string]any{"issuer": "https://x"} }
func (probeSvc) JWKS() map[string]any      { return map[string]any{"keys": []any{}} }

type probeAuth struct{}

func (probeAuth) Authenticate(context.Context, string) (middleware.Principal, error) {
	return middleware.Principal{UserID: 1, Scopes: []string{"openid"}}, nil
}

func TestProbeRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	denyAll := func(c *gin.Context) { c.AbortWithStatus(http.StatusTeapot) }
	RegisterRoutes(r, Handler{Service: probeSvc{}, Auth: probeAuth{}, ConsentURL: "https://front/consent"}, denyAll)

	type tc struct{ method, path, ct, body string }
	for _, x := range []tc{
		{"GET", "/oauth/authorize?client_id=a&redirect_uri=b&response_type=code&state=s&code_challenge=c&code_challenge_method=S256&scope=openid", "", ""},
		{"POST", "/oauth/token", "application/x-www-form-urlencoded", "grant_type=refresh_token&refresh_token=r"},
		{"POST", "/oauth/revoke", "application/x-www-form-urlencoded", "token=t&client_id=c"},
		{"GET", "/userinfo", "", ""},
		{"POST", "/userinfo", "", ""},
		{"GET", "/.well-known/openid-configuration", "", ""},
		{"GET", "/.well-known/jwks.json", "", ""},
		{"POST", "/oauth/authorize/consent", "application/json", `{"request_id":"ar_x","approve":true}`},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(x.method, x.path, strings.NewReader(x.body))
		if x.ct != "" {
			req.Header.Set("Content-Type", x.ct)
		}
		r.ServeHTTP(rec, req)
		t.Logf("%-6s %-62s -> %d  cache=%q loc=%q", x.method, x.path, rec.Code,
			rec.Header().Get("Cache-Control"), rec.Header().Get("Location"))
	}
}

// Probe: does UserInfo gate on principal scopes, and what does an auth failure emit?
type failAuth struct{}

func (failAuth) Authenticate(context.Context, string) (middleware.Principal, error) {
	return middleware.Principal{}, context.DeadlineExceeded
}

func TestProbeUserInfoAuthFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterRoutes(r, Handler{Service: probeSvc{}, Auth: failAuth{}, ConsentURL: "https://front/consent"}, func(c *gin.Context) {})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer bad")
	r.ServeHTTP(rec, req)
	t.Logf("userinfo authfail -> %d  www=%q body=%s", rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body.String())
}

// Probe: nil Auth on /userinfo
func TestProbeUserInfoNilAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterRoutes(r, Handler{Service: probeSvc{}, ConsentURL: "https://front/consent"}, func(c *gin.Context) {})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/userinfo", nil)
	r.ServeHTTP(rec, req)
	t.Logf("userinfo nilAuth -> %d www=%q body=%s", rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body.String())
}
