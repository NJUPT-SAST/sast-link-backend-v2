package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Lark (飞书) endpoint URLs.
const (
	larkAuthorizeURL      = "https://open.feishu.cn/open-apis/authen/v1/authorize"
	larkAppAccessTokenURL = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal" // #nosec G101 // Public Lark endpoint URL, not a credential.
	larkUserTokenURL      = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"             // #nosec G101 // Public Lark endpoint URL, not a credential.
	// larkOIDCTokenURL exchanges the login-free pre-authorization code the
	// Feishu client hands an embedded web app through the tt.requestAccess /
	// tt.requestAuthCode JSAPI. The authorize-page flow's codes
	// (larkUserTokenURL) and these are two families: each endpoint rejects the
	// other's codes.
	larkOIDCTokenURL = "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token" // #nosec G101 // Public Lark endpoint URL, not a credential.
	larkUserInfoURL  = "https://open.feishu.cn/open-apis/authen/v1/user_info"
)

// LarkConfig holds the app credentials, the registered callback, and the tenant
// this deployment accepts.
type LarkConfig struct {
	AppID       string
	AppSecret   string
	RedirectURI string
	// TenantKey restricts logins to one Lark tenant. PRD §4.5 limits Lark login
	// to the SAST enterprise; an empty value disables the check, which is only
	// appropriate in tests.
	TenantKey string
}

// LarkClient exchanges Lark authorization codes for account identities.
//
// The app_access_token is cached: it is app-level (not per-user), valid for two
// hours, and identical for every exchange, so re-fetching it on each login costs
// an outbound round trip and one Lark quota hit per login. The cache lives
// behind this client's interface — nothing in the callers needs to know. A burst
// of concurrent misses may each fetch once; the requests are idempotent.
type LarkClient struct {
	cfg    LarkConfig
	client Doer
	now    func() time.Time

	// tokenMu guards the cached app token and its expiry.
	tokenMu        sync.Mutex
	appToken       string
	appTokenExpiry time.Time
}

// refreshAppTokenLeadTime re-fetches a cached app token before it actually
// expires, so a token riding its final seconds never reaches Lark. Lark grants
// two hours; a minute of slack is plenty.
const refreshAppTokenLeadTime = time.Minute

// NewLark returns a LarkClient. A nil client falls back to NewHTTPClient and a
// nil clock to time.Now.
func NewLark(cfg LarkConfig, client Doer, now func() time.Time) *LarkClient {
	if client == nil {
		client = NewHTTPClient()
	}
	if now == nil {
		now = time.Now
	}
	return &LarkClient{cfg: cfg, client: client, now: now}
}

// AuthorizeURL builds the Lark authorization page URL for the given state.
func (c *LarkClient) AuthorizeURL(state string) string {
	query := url.Values{
		"app_id":       {c.cfg.AppID},
		"redirect_uri": {c.cfg.RedirectURI},
		"state":        {state},
	}
	return larkAuthorizeURL + "?" + query.Encode()
}

// larkAppAccessTokenResponse is the internal app_access_token reply. Lark signals
// application errors in the body's code field with HTTP 200, so code must be
// checked even on success.
type larkAppAccessTokenResponse struct {
	Code           int    `json:"code"`
	Msg            string `json:"msg"`
	AppAccessToken string `json:"app_access_token"`
	Expire         int    `json:"expire"`
}

// larkUserTokenResponse is the OAuth v2 token reply. This endpoint reports
// failures as a string error field alongside a non-2xx status.
type larkUserTokenResponse struct {
	Code             int    `json:"code"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
}

// larkOIDCTokenResponse is the v1 OIDC token reply used by the login-free
// flow. Like the app_access_token endpoint it reports application errors in
// the body's code field with HTTP 200, and wraps the payload in data.
type larkOIDCTokenResponse struct {
	Code int                  `json:"code"`
	Msg  string               `json:"msg"`
	Data larkOIDCTokenPayload `json:"data"`
}

// larkOIDCTokenPayload is the token subset inside the v1 OIDC reply.
type larkOIDCTokenPayload struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}

// larkUserInfoResponse wraps the user payload in Lark's envelope.
type larkUserInfoResponse struct {
	Code int          `json:"code"`
	Msg  string       `json:"msg"`
	Data larkUserData `json:"data"`
}

// larkUserData is the subset of the user_info payload this flow keeps.
//
// UnionID is the identifier used as provider_id: it is stable for one account
// across every app in the tenant, whereas OpenID varies per app and would break
// the binding as soon as a second app is registered.
type larkUserData struct {
	Name            string `json:"name"`
	EnName          string `json:"en_name"`
	AvatarURL       string `json:"avatar_url"`
	AvatarThumb     string `json:"avatar_thumb"`
	OpenID          string `json:"open_id"`
	UnionID         string `json:"union_id"`
	UserID          string `json:"user_id"`
	Email           string `json:"email"`
	EnterpriseEmail string `json:"enterprise_email"`
	Mobile          string `json:"mobile"`
	TenantKey       string `json:"tenant_key"`
	EmployeeNo      string `json:"employee_no"`
}

// Exchange turns an authorization code into a normalized Identity, rejecting
// accounts outside the configured tenant.
//
// redirectURI is the exact callback the code was issued against. RFC 6749
// §4.1.3 requires the token request to repeat it. An empty value falls back to
// the configured login callback (LarkConfig.RedirectURI), which is what the
// login flow uses; the bind flow passes the frontend bind callback instead.
func (c *LarkClient) Exchange(ctx context.Context, code, redirectURI string) (*Identity, error) {
	appToken, err := c.fetchAppAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	userToken, err := c.exchangeCode(ctx, appToken, code, redirectURI)
	if err != nil {
		return nil, err
	}
	user, err := c.fetchUserInfo(ctx, userToken.AccessToken)
	if err != nil {
		return nil, err
	}
	return c.identityFromUser(user, userToken.AccessToken, userToken.RefreshToken, userToken.ExpiresIn)
}

// ExchangeAppCode turns a login-free pre-authorization code — the one the
// Feishu client hands an embedded web app through the tt.requestAccess /
// tt.requestAuthCode JSAPI — into a normalized Identity, rejecting accounts
// outside the configured tenant.
//
// The token request carries neither redirect_uri nor client_secret: the
// endpoint authenticates the app through the app_access_token in the
// Authorization header, and the code never rode a redirect.
func (c *LarkClient) ExchangeAppCode(ctx context.Context, code string) (*Identity, error) {
	appToken, err := c.fetchAppAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	userToken, err := c.exchangeAppCode(ctx, appToken, code)
	if err != nil {
		return nil, err
	}
	user, err := c.fetchUserInfo(ctx, userToken.AccessToken)
	if err != nil {
		return nil, err
	}
	return c.identityFromUser(user, userToken.AccessToken, userToken.RefreshToken, userToken.ExpiresIn)
}

// identityFromUser normalizes a fetched Lark user into an Identity. Exchange
// and ExchangeAppCode share this tail so the union_id demand and the tenant
// gate cannot drift between the authorize-page flow and the login-free one.
func (c *LarkClient) identityFromUser(user *larkUserData, accessToken, refreshToken string, expiresIn int) (*Identity, error) {
	unionID := strings.TrimSpace(user.UnionID)
	if unionID == "" {
		// Without a union_id there is no stable key to bind. Falling back to
		// open_id would produce a binding that silently breaks when a second
		// Lark app is registered against the same tenant.
		return nil, fmt.Errorf("lark user_info has no union_id: %w", ErrUnexpectedResponse)
	}
	// The tenant gate runs before the identity is returned so a foreign-tenant
	// account never reaches the binding or registration branches.
	if c.cfg.TenantKey != "" && strings.TrimSpace(user.TenantKey) != c.cfg.TenantKey {
		return nil, fmt.Errorf("lark tenant %q is not the accepted tenant: %w",
			user.TenantKey, ErrForeignTenant)
	}

	displayName := strings.TrimSpace(user.Name)
	if displayName == "" {
		displayName = strings.TrimSpace(user.EnName)
	}
	return &Identity{
		ProviderID:  unionID,
		DisplayName: displayName,
		AvatarURL:   strings.TrimSpace(user.AvatarURL),
		// identity_data keeps both identifiers: union_id for traceability next
		// to provider_id, and open_id because Lark's messaging APIs address
		// users by it. Mobile and the email fields are deliberately omitted —
		// this column is read by admin tooling and does not need PII that the
		// flow itself never uses.
		Data: map[string]any{
			"name":       user.Name,
			"avatar_url": user.AvatarURL,
			"open_id":    user.OpenID,
			"union_id":   unionID,
			"tenant_key": user.TenantKey,
		},
		AccessToken:    accessToken,
		RefreshToken:   refreshToken,
		TokenExpiresAt: expiryFromSeconds(c.now(), expiresIn),
	}, nil
}

func (c *LarkClient) fetchAppAccessToken(ctx context.Context) (string, error) {
	if token := c.cachedAppToken(); token != "" {
		return token, nil
	}
	payload, err := json.Marshal(map[string]string{
		"app_id":     c.cfg.AppID,
		"app_secret": c.cfg.AppSecret,
	})
	if err != nil {
		return "", fmt.Errorf("encode lark app_access_token request: %w", err)
	}
	buildRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, larkAppAccessTokenURL,
			bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("build lark app_access_token request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		return req, nil
	}

	var response larkAppAccessTokenResponse
	if err := doJSONRetry(ctx, c.client, buildRequest, "lark app_access_token", &response); err != nil {
		return "", err
	}
	if response.Code != 0 {
		// A non-zero code here is a misconfigured app credential, not a bad
		// user code, so it stays an unexpected-response failure rather than
		// invalid_grant.
		return "", fmt.Errorf("lark app_access_token failed (code %d: %s): %w",
			response.Code, response.Msg, ErrUnexpectedResponse)
	}
	if strings.TrimSpace(response.AppAccessToken) == "" {
		return "", fmt.Errorf("lark app_access_token response is empty: %w", ErrUnexpectedResponse)
	}
	expiry := c.now().Add(time.Duration(response.Expire) * time.Second)
	c.tokenMu.Lock()
	c.appToken = response.AppAccessToken
	c.appTokenExpiry = expiry
	c.tokenMu.Unlock()
	return response.AppAccessToken, nil
}

// cachedAppToken returns the cached app token while it still has
// refreshAppTokenLeadTime of life left, or "" so the caller re-fetches.
func (c *LarkClient) cachedAppToken() string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.appToken == "" || !c.now().Before(c.appTokenExpiry.Add(-refreshAppTokenLeadTime)) {
		return ""
	}
	return c.appToken
}

func (c *LarkClient) exchangeCode(ctx context.Context, appToken, code, redirectURI string) (*larkUserTokenResponse, error) {
	redirect := strings.TrimSpace(redirectURI)
	if redirect == "" {
		redirect = c.cfg.RedirectURI
	}
	payload, err := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     c.cfg.AppID,
		"client_secret": c.cfg.AppSecret,
		"code":          code,
		"redirect_uri":  redirect,
	})
	if err != nil {
		return nil, fmt.Errorf("encode lark token request: %w", err)
	}
	buildTokenRequest := func() (*http.Request, error) {
		req, buildErr := http.NewRequestWithContext(ctx, http.MethodPost, larkUserTokenURL,
			bytes.NewReader(payload))
		if buildErr != nil {
			return nil, fmt.Errorf("build lark token request: %w", buildErr)
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Authorization", "Bearer "+appToken)
		return req, nil
	}

	var token larkUserTokenResponse
	err = doJSONRetry(ctx, c.client, buildTokenRequest, "lark token exchange", &token)
	if err != nil {
		// This endpoint reports a spent or forged code with a non-2xx status,
		// which doJSON surfaces as ErrUnexpectedResponse. Reclassify it: the
		// only input the user controls is the code, so a 4xx here is
		// invalid_grant and must not read as a provider outage.
		if isClientRejection(err) {
			return nil, fmt.Errorf("lark token exchange rejected the code: %w", ErrInvalidGrant)
		}
		return nil, err
	}
	if token.Error != "" {
		return nil, fmt.Errorf("lark token exchange rejected (%s: %s): %w",
			token.Error, token.ErrorDescription, ErrInvalidGrant)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return nil, fmt.Errorf("lark token exchange returned no access token: %w", ErrUnexpectedResponse)
	}
	return &token, nil
}

func (c *LarkClient) exchangeAppCode(ctx context.Context, appToken, code string) (*larkOIDCTokenPayload, error) {
	payload, err := json.Marshal(map[string]string{
		"grant_type": "authorization_code",
		"code":       code,
	})
	if err != nil {
		return nil, fmt.Errorf("encode lark oidc token request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, larkOIDCTokenURL,
		bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build lark oidc token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+appToken)

	var response larkOIDCTokenResponse
	if err := doJSON(ctx, c.client, req, "lark oidc token exchange", &response); err != nil {
		return nil, err
	}
	if response.Code != 0 {
		// 20003/20004 mean the pre-authorization code was spent or expired — the
		// only input the caller controls, so they read as invalid_grant rather
		// than an app-side fault. Everything else is a credential or provider
		// problem the caller cannot fix by retrying with a new code.
		if response.Code == 20003 || response.Code == 20004 {
			return nil, fmt.Errorf("lark oidc token exchange rejected the code (code %d: %s): %w",
				response.Code, response.Msg, ErrInvalidGrant)
		}
		return nil, fmt.Errorf("lark oidc token exchange failed (code %d: %s): %w",
			response.Code, response.Msg, ErrUnexpectedResponse)
	}
	if strings.TrimSpace(response.Data.AccessToken) == "" {
		return nil, fmt.Errorf("lark oidc token exchange returned no access token: %w", ErrUnexpectedResponse)
	}
	return &response.Data, nil
}

func (c *LarkClient) fetchUserInfo(ctx context.Context, userAccessToken string) (*larkUserData, error) {
	buildUserRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, larkUserInfoURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build lark user_info request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+userAccessToken)
		return req, nil
	}

	var response larkUserInfoResponse
	if err := doJSONRetry(ctx, c.client, buildUserRequest, "lark fetch user_info", &response); err != nil {
		return nil, err
	}
	if response.Code != 0 {
		return nil, fmt.Errorf("lark user_info failed (code %d: %s): %w",
			response.Code, response.Msg, ErrUnexpectedResponse)
	}
	return &response.Data, nil
}
