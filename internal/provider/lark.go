package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Lark (飞书) endpoint URLs.
const (
	larkAuthorizeURL      = "https://open.feishu.cn/open-apis/authen/v1/authorize"
	larkAppAccessTokenURL = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal" //nolint:gosec // Public Lark endpoint URL, not a credential.
	larkUserTokenURL      = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"             //nolint:gosec // Public Lark endpoint URL, not a credential.
	larkUserInfoURL       = "https://open.feishu.cn/open-apis/authen/v1/user_info"
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
// The app_access_token is fetched per exchange rather than cached. Caching it
// would add a second expiry to reason about and a Redis key the PRD does not
// define, in exchange for one saved round trip on a flow that already makes
// several; if login latency ever justifies it, the cache belongs behind this
// client's interface and not in its callers.
type LarkClient struct {
	cfg    LarkConfig
	client Doer
	now    func() time.Time
}

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
func (c *LarkClient) Exchange(ctx context.Context, code string) (*Identity, error) {
	appToken, err := c.fetchAppAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	userToken, err := c.exchangeCode(ctx, appToken, code)
	if err != nil {
		return nil, err
	}
	user, err := c.fetchUserInfo(ctx, userToken.AccessToken)
	if err != nil {
		return nil, err
	}

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
		AccessToken:    userToken.AccessToken,
		RefreshToken:   userToken.RefreshToken,
		TokenExpiresAt: expiryFromSeconds(c.now(), userToken.ExpiresIn),
	}, nil
}

func (c *LarkClient) fetchAppAccessToken(ctx context.Context) (string, error) {
	payload, err := json.Marshal(map[string]string{
		"app_id":     c.cfg.AppID,
		"app_secret": c.cfg.AppSecret,
	})
	if err != nil {
		return "", fmt.Errorf("encode lark app_access_token request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, larkAppAccessTokenURL,
		bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("build lark app_access_token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	var response larkAppAccessTokenResponse
	if err := doJSON(ctx, c.client, req, "lark app_access_token", &response); err != nil {
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
	return response.AppAccessToken, nil
}

func (c *LarkClient) exchangeCode(ctx context.Context, appToken, code string) (*larkUserTokenResponse, error) {
	payload, err := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     c.cfg.AppID,
		"client_secret": c.cfg.AppSecret,
		"code":          code,
		"redirect_uri":  c.cfg.RedirectURI,
	})
	if err != nil {
		return nil, fmt.Errorf("encode lark token request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, larkUserTokenURL,
		bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build lark token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+appToken)

	var token larkUserTokenResponse
	err = doJSON(ctx, c.client, req, "lark token exchange", &token)
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

func (c *LarkClient) fetchUserInfo(ctx context.Context, userAccessToken string) (*larkUserData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, larkUserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build lark user_info request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+userAccessToken)

	var response larkUserInfoResponse
	if err := doJSON(ctx, c.client, req, "lark fetch user_info", &response); err != nil {
		return nil, err
	}
	if response.Code != 0 {
		return nil, fmt.Errorf("lark user_info failed (code %d: %s): %w",
			response.Code, response.Msg, ErrUnexpectedResponse)
	}
	return &response.Data, nil
}
