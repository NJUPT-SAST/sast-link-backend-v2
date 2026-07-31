package provider

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func githubTestClient(doer Doer) *GitHubClient {
	return NewGitHub(GitHubConfig{
		ClientID:     "gh-client",
		ClientSecret: "gh-secret",
		RedirectURI:  "https://link.sast.fun/v2/oauth/github/callback",
	}, doer, fixedClock())
}

func TestGitHubAuthorizeURLCarriesStateAndScope(t *testing.T) {
	client := githubTestClient(&fakeDoer{})
	got := client.AuthorizeURL("state-abc")

	if !strings.HasPrefix(got, githubAuthorizeURL+"?") {
		t.Fatalf("authorize URL = %q, want the GitHub authorize endpoint", got)
	}
	for _, want := range []string{
		"client_id=gh-client",
		"state=state-abc",
		"scope=read%3Auser",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("authorize URL %q is missing %q", got, want)
		}
	}
	// user:email would grant access to private addresses this flow never reads.
	if strings.Contains(got, "user%3Aemail") {
		t.Fatalf("authorize URL %q requests the email scope", got)
	}
}

func TestGitHubExchangeReturnsIdentity(t *testing.T) {
	doer := &fakeDoer{responses: map[string]fakeResponse{
		githubTokenURL: {status: http.StatusOK, body: `{
			"access_token":"gho_token","refresh_token":"ghr_token",
			"expires_in":28800,"token_type":"bearer","scope":"read:user"}`},
		githubUserURL: {status: http.StatusOK, body: `{
			"id":145339646,"login":"ptilopsis","name":"Ptilopsis",
			"avatar_url":"https://avatars.githubusercontent.com/u/145339646"}`},
	}}
	identity, err := githubTestClient(doer).Exchange(context.Background(), "code-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	// provider_id must be the immutable numeric ID, not the renameable handle.
	if identity.ProviderID != "145339646" {
		t.Fatalf("ProviderID = %q, want \"145339646\"", identity.ProviderID)
	}
	if identity.DisplayName != "Ptilopsis" {
		t.Fatalf("DisplayName = %q, want \"Ptilopsis\"", identity.DisplayName)
	}
	if identity.Data["login"] != "ptilopsis" {
		t.Fatalf("identity_data login = %v, want \"ptilopsis\"", identity.Data["login"])
	}
	if identity.AccessToken != "gho_token" || identity.RefreshToken != "ghr_token" {
		t.Fatalf("tokens = %q/%q, want gho_token/ghr_token", identity.AccessToken, identity.RefreshToken)
	}
	if identity.TokenExpiresAt == nil {
		t.Fatal("TokenExpiresAt = nil, want an absolute instant derived from expires_in")
	}

	tokenReq := doer.requestFor(t, githubTokenURL)
	// Without Accept: application/json GitHub replies form-encoded and the
	// decode would fail on a response that is otherwise correct.
	if tokenReq.header.Get("Accept") != "application/json" {
		t.Fatalf("token request Accept = %q, want application/json", tokenReq.header.Get("Accept"))
	}
	if !strings.Contains(tokenReq.body, "code=code-1") {
		t.Fatalf("token request body %q is missing the code", tokenReq.body)
	}
	userReq := doer.requestFor(t, githubUserURL)
	if userReq.header.Get("Authorization") != "Bearer gho_token" {
		t.Fatalf("user request Authorization = %q", userReq.header.Get("Authorization"))
	}
	if userReq.header.Get("X-GitHub-Api-Version") != githubAPIVersion {
		t.Fatalf("user request API version = %q, want %q",
			userReq.header.Get("X-GitHub-Api-Version"), githubAPIVersion)
	}
}

func TestGitHubExchangeMapsBodyErrorToInvalidGrant(t *testing.T) {
	// GitHub answers a spent code with HTTP 200 plus an error field, so reading
	// only the status would treat this as a success.
	doer := &fakeDoer{responses: map[string]fakeResponse{
		githubTokenURL: {status: http.StatusOK, body: `{
			"error":"bad_verification_code",
			"error_description":"The code passed is incorrect or expired."}`},
	}}
	_, err := githubTestClient(doer).Exchange(context.Background(), "spent")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("error = %v, want ErrInvalidGrant", err)
	}
}

func TestGitHubExchangeRejectsMissingAccessToken(t *testing.T) {
	doer := &fakeDoer{responses: map[string]fakeResponse{
		githubTokenURL: {status: http.StatusOK, body: `{"token_type":"bearer"}`},
	}}
	_, err := githubTestClient(doer).Exchange(context.Background(), "code-1")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("error = %v, want ErrUnexpectedResponse", err)
	}
}

func TestGitHubExchangeRejectsZeroUserID(t *testing.T) {
	// A zero ID would be formatted as "0" and collide every such login onto one
	// binding, so it has to be refused rather than stored.
	doer := &fakeDoer{responses: map[string]fakeResponse{
		githubTokenURL: {status: http.StatusOK, body: `{"access_token":"gho_token"}`},
		githubUserURL:  {status: http.StatusOK, body: `{"login":"ghost"}`},
	}}
	_, err := githubTestClient(doer).Exchange(context.Background(), "code-1")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("error = %v, want ErrUnexpectedResponse", err)
	}
}

func TestGitHubExchangeFallsBackToLoginForDisplayName(t *testing.T) {
	doer := &fakeDoer{responses: map[string]fakeResponse{
		githubTokenURL: {status: http.StatusOK, body: `{"access_token":"gho_token"}`},
		githubUserURL:  {status: http.StatusOK, body: `{"id":7,"login":"ptilopsis","name":""}`},
	}}
	identity, err := githubTestClient(doer).Exchange(context.Background(), "code-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.DisplayName != "ptilopsis" {
		t.Fatalf("DisplayName = %q, want the login handle as fallback", identity.DisplayName)
	}
}

func TestGitHubExchangeOmitsExpiryWhenProviderSaysNothing(t *testing.T) {
	// GitHub OAuth apps without token expiry omit expires_in. Deriving an
	// expiry from a zero value would persist one already in the past.
	doer := &fakeDoer{responses: map[string]fakeResponse{
		githubTokenURL: {status: http.StatusOK, body: `{"access_token":"gho_token"}`},
		githubUserURL:  {status: http.StatusOK, body: `{"id":7,"login":"ptilopsis"}`},
	}}
	identity, err := githubTestClient(doer).Exchange(context.Background(), "code-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.TokenExpiresAt != nil {
		t.Fatalf("TokenExpiresAt = %v, want nil when expires_in is absent", identity.TokenExpiresAt)
	}
}
