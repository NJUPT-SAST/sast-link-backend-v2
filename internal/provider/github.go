package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// GitHub endpoint URLs. They are constants rather than configuration because
// GitHub serves one global instance; a GitHub Enterprise deployment would need
// its own client, not a reconfigured one.
const (
	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token" //nolint:gosec // Public GitHub endpoint URL, not a credential.
	githubUserURL      = "https://api.github.com/user"
)

// githubAPIVersion pins the REST API version so a future default change at
// GitHub cannot alter the response shape this client parses.
const githubAPIVersion = "2022-11-28"

// GitHubConfig holds the OAuth app credentials and the callback this service
// registered with GitHub.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// GitHubClient exchanges GitHub authorization codes for account identities.
type GitHubClient struct {
	cfg    GitHubConfig
	client Doer
	now    func() time.Time
}

// NewGitHub returns a GitHubClient. A nil client falls back to NewHTTPClient and
// a nil clock to time.Now, so production wiring can pass only the config.
func NewGitHub(cfg GitHubConfig, client Doer, now func() time.Time) *GitHubClient {
	if client == nil {
		client = NewHTTPClient()
	}
	if now == nil {
		now = time.Now
	}
	return &GitHubClient{cfg: cfg, client: client, now: now}
}

// AuthorizeURL builds the page to redirect the user to. The state is generated
// and stored by the caller; this client only places it in the query.
//
// The requested scope is "read:user" — enough to read the public profile that
// identifies the account, and deliberately not "user:email", which would grant
// access to private addresses this flow has no use for.
func (c *GitHubClient) AuthorizeURL(state string) string {
	query := url.Values{
		"client_id":     {c.cfg.ClientID},
		"redirect_uri":  {c.cfg.RedirectURI},
		"scope":         {"read:user"},
		"state":         {state},
		"allow_signup":  {"false"},
		"response_type": {"code"},
	}
	return githubAuthorizeURL + "?" + query.Encode()
}

// githubTokenResponse covers both the success and failure shapes. GitHub answers
// a rejected code with HTTP 200 and an "error" field, so the error must be read
// from the body rather than the status.
type githubTokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	Scope            string `json:"scope"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// githubUser is the subset of GET /user this flow needs. ID is numeric and
// immutable; Login is the renameable handle, so it is stored as metadata only.
type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

// Exchange turns an authorization code into a normalized Identity.
func (c *GitHubClient) Exchange(ctx context.Context, code string) (*Identity, error) {
	token, err := c.exchangeCode(ctx, code)
	if err != nil {
		return nil, err
	}
	user, err := c.fetchUser(ctx, token.AccessToken)
	if err != nil {
		return nil, err
	}
	// A zero ID means the response decoded but carried no account. Treating it
	// as valid would write an identity keyed on "0" and collide every such
	// login onto one binding.
	if user.ID == 0 {
		return nil, fmt.Errorf("github user response has no id: %w", ErrUnexpectedResponse)
	}

	identity := &Identity{
		ProviderID:  strconv.FormatInt(user.ID, 10),
		DisplayName: strings.TrimSpace(user.Name),
		AvatarURL:   strings.TrimSpace(user.AvatarURL),
		// identities.identity_data for github carries the login handle, per
		// docs/psql-db-design.md. It is display metadata, not an identifier.
		Data: map[string]any{
			"login": user.Login,
		},
		AccessToken:    token.AccessToken,
		RefreshToken:   token.RefreshToken,
		TokenExpiresAt: expiryFromSeconds(c.now(), token.ExpiresIn),
	}
	// GitHub's "name" is optional and often empty; fall back to the handle so
	// the registration branch can still prefill something meaningful.
	if identity.DisplayName == "" {
		identity.DisplayName = strings.TrimSpace(user.Login)
	}
	return identity, nil
}

func (c *GitHubClient) exchangeCode(ctx context.Context, code string) (*githubTokenResponse, error) {
	form := url.Values{
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {c.cfg.RedirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build github token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Without this GitHub returns a form-encoded body instead of JSON.
	req.Header.Set("Accept", "application/json")

	var token githubTokenResponse
	if err := doJSON(ctx, c.client, req, "github token exchange", &token); err != nil {
		return nil, err
	}
	if token.Error != "" {
		// Any error here traces back to the code the user's browser carried, so
		// the whole class maps to invalid_grant. The provider's own wording is
		// kept for the log, not for the user.
		return nil, fmt.Errorf("github token exchange rejected (%s: %s): %w",
			token.Error, token.ErrorDescription, ErrInvalidGrant)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return nil, fmt.Errorf("github token exchange returned no access token: %w", ErrUnexpectedResponse)
	}
	return &token, nil
}

func (c *GitHubClient) fetchUser(ctx context.Context, accessToken string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubUserURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build github user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)

	var user githubUser
	if err := doJSON(ctx, c.client, req, "github fetch user", &user); err != nil {
		return nil, err
	}
	return &user, nil
}
