package oauth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

func TestAuthorizeStashesValidatedRequest(t *testing.T) {
	h := newHarness(t)

	result, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if !strings.HasPrefix(result.RequestID, authorizeRequestIDPrefix) {
		t.Fatalf("request ID = %q, want the %q prefix", result.RequestID, authorizeRequestIDPrefix)
	}
	if result.ClientName != "SAST Link Web" || result.ExpiresIn != 600 {
		t.Fatalf("result = %+v, want the client name and a 600s stash", result)
	}

	stashed, found, err := h.requests.ConsumeAuthorizeRequest(context.Background(), result.RequestID)
	if err != nil || !found {
		t.Fatalf("stash lookup = %v, found %v; want the saved payload", err, found)
	}
	// The stash must carry every parameter the code is built from; anything read
	// back off the consent request instead would be attacker-controlled.
	if stashed.ClientID != testPublicClientID || stashed.RedirectURI != testRedirectURI ||
		stashed.State != "client-state" || stashed.Nonce != "n-0S6_WzA2Mj" ||
		stashed.CodeChallenge != testChallenge(t) || stashed.CodeChallengeMethod != pkceMethodS256 {
		t.Fatalf("stashed payload = %+v, want every validated request parameter", stashed)
	}
	if strings.Join(stashed.Scopes, " ") != "openid profile email" {
		t.Fatalf("stashed scopes = %v, want canonical openid profile email", stashed.Scopes)
	}
}

// The redirectability split is the open-redirect defense: nothing may bounce to a
// redirect_uri before that URI has been matched against the client's registration.
func TestAuthorizeWithholdsRedirectUntilClientAndURIVerified(t *testing.T) {
	h := newHarness(t)

	nonRedirectable := []struct {
		name     string
		mutate   func(*AuthorizeInput)
		wantCode string
	}{
		{
			name:     "empty client_id",
			mutate:   func(i *AuthorizeInput) { i.ClientID = "" },
			wantCode: ErrorInvalidRequest,
		},
		{
			name:     "unknown client",
			mutate:   func(i *AuthorizeInput) { i.ClientID = "no-such-client" },
			wantCode: ErrorInvalidClient,
		},
		{
			name:     "empty redirect_uri",
			mutate:   func(i *AuthorizeInput) { i.RedirectURI = "" },
			wantCode: ErrorInvalidRequest,
		},
		{
			name:     "unregistered redirect_uri",
			mutate:   func(i *AuthorizeInput) { i.RedirectURI = "https://attacker.test/steal" },
			wantCode: ErrorInvalidRequest,
		},
		{
			// A registered prefix is not a match: appending a path must not be enough
			// to have the code delivered somewhere the client never registered.
			name:     "registered prefix with extra path",
			mutate:   func(i *AuthorizeInput) { i.RedirectURI = testRedirectURI + "/../evil" },
			wantCode: ErrorInvalidRequest,
		},
	}
	for _, test := range nonRedirectable {
		t.Run(test.name, func(t *testing.T) {
			input := validAuthorizeInput(t)
			test.mutate(&input)
			_, err := h.service.Authorize(context.Background(), input)
			oauthErr := oauthError(t, err, test.wantCode)
			if oauthErr.Redirectable {
				t.Fatal("error is redirectable before redirect_uri was verified; open-redirect risk")
			}
		})
	}

	redirectable := []struct {
		name     string
		mutate   func(*AuthorizeInput)
		wantCode string
	}{
		{
			name:     "wrong response_type",
			mutate:   func(i *AuthorizeInput) { i.ResponseType = "token" },
			wantCode: ErrorUnsupportedResponse,
		},
		{
			name:     "missing state",
			mutate:   func(i *AuthorizeInput) { i.State = "  " },
			wantCode: ErrorInvalidRequest,
		},
		{
			name:     "plain PKCE method",
			mutate:   func(i *AuthorizeInput) { i.CodeChallengeMethod = "plain" },
			wantCode: ErrorInvalidRequest,
		},
		{
			name:     "missing code_challenge",
			mutate:   func(i *AuthorizeInput) { i.CodeChallenge = "" },
			wantCode: ErrorInvalidRequest,
		},
		{
			name:     "scope without openid",
			mutate:   func(i *AuthorizeInput) { i.Scope = "profile email" },
			wantCode: ErrorInvalidScope,
		},
		{
			name:     "unsupported scope",
			mutate:   func(i *AuthorizeInput) { i.Scope = "openid admin" },
			wantCode: ErrorInvalidScope,
		},
	}
	for _, test := range redirectable {
		t.Run(test.name, func(t *testing.T) {
			input := validAuthorizeInput(t)
			test.mutate(&input)
			_, err := h.service.Authorize(context.Background(), input)
			oauthErr := oauthError(t, err, test.wantCode)
			if !oauthErr.Redirectable {
				t.Fatal("error is not redirectable although the client and redirect_uri were verified")
			}
		})
	}
}

func TestAuthorizeAcceptsExtraSpacesInScope(t *testing.T) {
	h := newHarness(t)
	input := validAuthorizeInput(t)
	input.Scope = "  openid   profile  "

	result, err := h.service.Authorize(context.Background(), input)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	stashed, _, _ := h.requests.ConsumeAuthorizeRequest(context.Background(), result.RequestID)
	if strings.Join(stashed.Scopes, " ") != "openid profile" {
		t.Fatalf("stashed scopes = %v, want openid profile", stashed.Scopes)
	}
}

// PRD §4.10: a third-party client is confined to the scopes it registered, while
// a first-party client may ask for anything supported.
func TestAuthorizeEnforcesThirdPartyScopeRegistration(t *testing.T) {
	h := newHarness(t)

	input := validAuthorizeInput(t)
	input.ClientID = testConfidentialClientID
	input.Scope = "openid profile email" // email is not registered

	_, err := h.service.Authorize(context.Background(), input)
	oauthErr := oauthError(t, err, ErrorInvalidScope)
	if !oauthErr.Redirectable {
		t.Fatal("scope-limit error should be redirectable")
	}

	input.Scope = "openid profile"
	if _, err := h.service.Authorize(context.Background(), input); err != nil {
		t.Fatalf("Authorize() within registered scope error = %v", err)
	}

	// The first-party client registered the same three scopes but is not confined
	// to them by the client-type rule.
	firstParty := validAuthorizeInput(t)
	firstParty.Scope = "openid profile email"
	if _, err := h.service.Authorize(context.Background(), firstParty); err != nil {
		t.Fatalf("Authorize() first-party error = %v", err)
	}
}

func TestAuthorizeRejectsClientWithoutAuthorizationCodeGrant(t *testing.T) {
	h := newHarness(t)
	h.clients.byClientID[testPublicClientID].GrantTypes = model.StringArray{grantTypeRefreshToken}

	_, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	requireOAuthError(t, err, ErrorUnauthorizedClient)
}

// The stash is the only copy of the request, so a write that cannot be confirmed
// must fail closed rather than report a pending authorization that does not exist.
func TestAuthorizeFailsClosedWhenStashUnavailable(t *testing.T) {
	h := newHarness(t)
	h.requests.saveErr = errors.New("redis down")

	_, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	oauthErr := oauthError(t, err, ErrorTemporarilyUnavail)
	if oauthErr.Kind != KindDependencyUnavailable {
		t.Fatalf("kind = %q, want %q", oauthErr.Kind, KindDependencyUnavailable)
	}
}

func TestAuthorizeThrottlesByIP(t *testing.T) {
	h := newHarness(t)
	h.limiter.result = LimitResult{Allowed: false, RetryAfter: 30 * time.Second}

	_, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	oauthErr := oauthError(t, err, ErrorTemporarilyUnavail)
	if oauthErr.Kind != KindRateLimited || oauthErr.RetryAfter != 30*time.Second {
		t.Fatalf("error = %+v, want a rate-limited error carrying Retry-After", oauthErr)
	}
	calls := h.limiter.callsSnapshot()
	if len(calls) != 1 || calls[0] != "authorize:ip:203.0.113.10" {
		t.Fatalf("limiter calls = %v, want one keyed by caller IP", calls)
	}
}

// A limiter outage must not take third-party login down; the limiter exists to
// bound stash writes, not to authenticate.

// The consent submission mints codes, so it gets its own per-user budget rather
// than riding the peek's. Keyed by user because campus egress shares one NAT IP.
func TestConsentThrottlesByUser(t *testing.T) {
	h := newHarness(t)
	h.limiter.result = LimitResult{Allowed: false, RetryAfter: 30 * time.Second}

	_, err := h.service.Consent(context.Background(), ConsentInput{RequestID: "ar_x", Approve: true, UserID: 1})
	oauthErr := oauthError(t, err, ErrorTemporarilyUnavail)
	if oauthErr.Kind != KindRateLimited || oauthErr.RetryAfter != 30*time.Second {
		t.Fatalf("error = %+v, want a rate-limited error carrying Retry-After", oauthErr)
	}
	calls := h.limiter.callsSnapshot()
	if len(calls) != 1 || calls[0] != "oauth_consent:user:1" {
		t.Fatalf("limiter calls = %v, want one keyed by user", calls)
	}
}

func TestAuthorizeFailsOpenWhenLimiterErrors(t *testing.T) {
	h := newHarness(t)
	h.limiter.err = errors.New("redis down")

	if _, err := h.service.Authorize(context.Background(), validAuthorizeInput(t)); err != nil {
		t.Fatalf("Authorize() error = %v, want the limiter outage to fail open", err)
	}
}

func TestConsentIssuesCodeAndRedirect(t *testing.T) {
	h := newHarness(t)
	authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	result, err := h.service.Consent(context.Background(), ConsentInput{
		RequestID: authorized.RequestID,
		Approve:   true,
		UserID:    1,
		ClientIP:  "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("Consent() error = %v", err)
	}

	parsed, err := url.Parse(result.RedirectURI)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	query := parsed.Query()
	code := query.Get("code")
	if !strings.HasPrefix(code, authorizationCodePrefix) {
		t.Fatalf("code = %q, want the %q prefix", code, authorizationCodePrefix)
	}
	// state must come back byte-for-byte: the client compares it to detect CSRF.
	if query.Get("state") != "client-state" {
		t.Fatalf("state = %q, want the client's original value", query.Get("state"))
	}
	if query.Get("error") != "" {
		t.Fatalf("redirect carries error = %q on success", query.Get("error"))
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != testRedirectURI {
		t.Fatalf("redirect target = %q, want the registered redirect_uri", parsed.String())
	}

	if len(h.authorizations.created) != 1 {
		t.Fatalf("created authorizations = %d, want 1", len(h.authorizations.created))
	}
	stored := h.authorizations.created[0]
	if stored.CodeChallenge != testChallenge(t) || stored.CodeChallengeMethod != pkceMethodS256 {
		t.Fatalf("stored PKCE = %q/%q, want the stashed challenge", stored.CodeChallenge, stored.CodeChallengeMethod)
	}
	if stored.Nonce == nil || *stored.Nonce != "n-0S6_WzA2Mj" {
		t.Fatalf("stored nonce = %v, want the request nonce", stored.Nonce)
	}
	// A family must exist on the code: it is what a later replay revokes.
	if stored.FamilyID == nil || *stored.FamilyID == "" {
		t.Fatal("stored authorization has no family ID; a code replay could not cascade")
	}
	if !stored.ExpiresAt.Equal(h.clock.value.Add(5 * time.Minute)) {
		t.Fatalf("code expiry = %v, want 5 minutes from now", stored.ExpiresAt)
	}
	if !stored.CreatedAt.Equal(h.clock.value) {
		t.Fatalf("code created_at = %v, want now; it backs the ID Token auth_time", stored.CreatedAt)
	}
	if actions := h.audit.actions(); len(actions) != 1 || actions[0] != "oauth_authorize" {
		t.Fatalf("audit actions = %v, want one oauth_authorize", actions)
	}
}

// RFC 6749 §4.1.2.1: a refusal is reported to the client as access_denied, not
// swallowed, so the client stops waiting.
func TestConsentDenialRedirectsAccessDenied(t *testing.T) {
	h := newHarness(t)
	authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	result, err := h.service.Consent(context.Background(), ConsentInput{
		RequestID: authorized.RequestID,
		Approve:   false,
		UserID:    1,
	})
	if err != nil {
		t.Fatalf("Consent(deny) error = %v, want a redirect rather than an error", err)
	}
	query := mustQuery(t, result.RedirectURI)
	if query.Get("error") != ErrorAccessDenied || query.Get("state") != "client-state" {
		t.Fatalf("denial redirect = %q, want access_denied with the original state", result.RedirectURI)
	}
	if query.Get("code") != "" {
		t.Fatal("denial redirect carries an authorization code")
	}
	if len(h.authorizations.created) != 0 {
		t.Fatal("denial created an authorization code")
	}
}

// One stash yields at most one code. Without atomic consumption, a double-submit
// of the consent page would mint two codes from one user decision.
func TestConsentConsumesStashExactlyOnce(t *testing.T) {
	h := newHarness(t)
	authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	const contenders = 6
	start := make(chan struct{})
	results := make(chan error, contenders)
	var waitGroup sync.WaitGroup
	waitGroup.Add(contenders)
	for range contenders {
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := h.service.Consent(context.Background(), ConsentInput{
				RequestID: authorized.RequestID,
				Approve:   true,
				UserID:    1,
			})
			results <- err
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		requireOAuthError(t, err, ErrorInvalidRequest)
	}
	if successes != 1 {
		t.Fatalf("concurrent Consent successes = %d, want 1", successes)
	}
	if len(h.authorizations.created) != 1 {
		t.Fatalf("created authorizations = %d, want 1", len(h.authorizations.created))
	}
}

func TestConsentRejectsUnknownStashAndBadPrincipal(t *testing.T) {
	h := newHarness(t)

	if _, err := h.service.Consent(context.Background(), ConsentInput{RequestID: "ar_missing", Approve: true, UserID: 1}); err != nil {
		requireOAuthError(t, err, ErrorInvalidRequest)
	} else {
		t.Fatal("Consent(unknown stash) returned no error")
	}

	authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if _, err := h.service.Consent(context.Background(), ConsentInput{RequestID: authorized.RequestID, Approve: true, UserID: 0}); err != nil {
		requireOAuthError(t, err, ErrorInvalidToken)
	} else {
		t.Fatal("Consent(no principal) returned no error")
	}
}

func TestConsentRejectsDeletedAccount(t *testing.T) {
	h := newHarness(t)
	h.users.byID[1].State = model.UserStateDeleted
	authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	_, err = h.service.Consent(context.Background(), ConsentInput{
		RequestID: authorized.RequestID,
		Approve:   true,
		UserID:    1,
	})
	requireOAuthError(t, err, ErrorAccessDenied)
	if len(h.authorizations.created) != 0 {
		t.Fatal("a deleted account was issued an authorization code")
	}
}

// A client disabled between the two legs must not receive a code. The stash is
// already spent at that point, so the user restarts.
func TestConsentRejectsClientDisabledBetweenLegs(t *testing.T) {
	h := newHarness(t)
	authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	delete(h.clients.byClientID, testPublicClientID)

	_, err = h.service.Consent(context.Background(), ConsentInput{
		RequestID: authorized.RequestID,
		Approve:   true,
		UserID:    1,
	})
	requireOAuthError(t, err, ErrorInvalidClient)
}

// A redirect_uri that already carries query parameters must keep them: dropping
// them would break clients that encode routing state in the callback URL.
func TestConsentPreservesExistingRedirectQuery(t *testing.T) {
	h := newHarness(t)
	withQuery := testRedirectURI + "?tenant=sast"
	h.clients.byClientID[testPublicClientID].RedirectURIs = model.StringArray{withQuery}

	input := validAuthorizeInput(t)
	input.RedirectURI = withQuery
	authorized, err := h.service.Authorize(context.Background(), input)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	result, err := h.service.Consent(context.Background(), ConsentInput{
		RequestID: authorized.RequestID,
		Approve:   true,
		UserID:    1,
	})
	if err != nil {
		t.Fatalf("Consent() error = %v", err)
	}
	query := mustQuery(t, result.RedirectURI)
	if query.Get("tenant") != "sast" || query.Get("code") == "" {
		t.Fatalf("redirect = %q, want the client's own query preserved alongside code", result.RedirectURI)
	}
}

func mustQuery(t *testing.T, rawURL string) url.Values {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return parsed.Query()
}

// state must survive byte for byte. It is the client's CSRF token and the client
// compares the echoed value against what it sent, so normalizing it — even just
// trimming whitespace — silently breaks login for that client. RFC 6749 §4.1.2.
func TestAuthorizePreservesStateExactly(t *testing.T) {
	h := newHarness(t)
	input := validAuthorizeInput(t)
	input.State = "  state with spaces\tand a tab  "

	result, err := h.service.Authorize(context.Background(), input)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	stashed, found, err := h.requests.ConsumeAuthorizeRequest(context.Background(), result.RequestID)
	if err != nil || !found {
		t.Fatalf("stash lookup = %v, found %v", err, found)
	}
	if stashed.State != input.State {
		t.Fatalf("stashed state = %q, want the original %q", stashed.State, input.State)
	}
}

// Whitespace alone is still not a state, so presence is checked on the trimmed
// value even though the original is what gets echoed.
func TestAuthorizeRejectsWhitespaceOnlyState(t *testing.T) {
	h := newHarness(t)
	input := validAuthorizeInput(t)
	input.State = " \t "

	_, err := h.service.Authorize(context.Background(), input)
	var oauthErr *Error
	if !errors.As(err, &oauthErr) || oauthErr.Code != ErrorInvalidRequest {
		t.Fatalf("error = %v, want invalid_request", err)
	}
}

// The registration can change between the two legs. An administrator who removes a
// compromised callback expects codes to stop going there at once; reading the
// redirect_uri from the stash alone kept delivering to it for the rest of the TTL.
func TestConsentRejectsRedirectURIRemovedBetweenLegs(t *testing.T) {
	h := newHarness(t)
	result, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	h.clients.byClientID[testPublicClientID].RedirectURIs = model.StringArray{"https://new.test/cb"}

	_, err = h.service.Consent(context.Background(), ConsentInput{
		RequestID: result.RequestID, Approve: true, UserID: 1,
	})

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Consent() error = %v, want ErrInvalidRequest", err)
	}
	if len(h.authorizations.created) != 0 {
		t.Fatalf("created %d codes, want none for a de-registered redirect_uri",
			len(h.authorizations.created))
	}
}

// Scopes are re-checked between the legs for the same reason as the redirect_uri, and
// it matters most for the admin scopes: revoking a client's delegated administration
// has to stop administrative codes at once, not once the stash expires. Without this
// the console's revocation left a window equal to the authorize-request TTL in which
// the client could still complete a consent it had already started.
func TestConsentRejectsScopeRemovedBetweenLegs(t *testing.T) {
	h := newHarness(t)
	delegated := h.clients.byClientID[testConfidentialClientID]
	delegated.Scopes = model.StringArray{"openid", scope.AdminRead}

	input := validAuthorizeInput(t)
	input.ClientID = testConfidentialClientID
	input.Scope = "openid " + scope.AdminRead
	result, err := h.service.Authorize(context.Background(), input)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	// The operator revokes delegated administration while the consent page is open.
	delegated.Scopes = model.StringArray{"openid"}

	_, err = h.service.Consent(context.Background(), ConsentInput{
		RequestID: result.RequestID, Approve: true, UserID: 1,
	})

	requireOAuthError(t, err, ErrorInvalidScope)
	if len(h.authorizations.created) != 0 {
		t.Fatalf("created %d codes, want none once the scope was revoked",
			len(h.authorizations.created))
	}
	// Non-redirectable: the request was valid when made, so the user is told to restart
	// rather than the client being handed an error about a change it did not cause.
	var oauthErr *Error
	if errors.As(err, &oauthErr) && oauthErr.Redirectable {
		t.Fatal("the scope re-check error must not be redirectable")
	}
	// The refusal is audited: an operator's mid-flight revocation that kills an
	// in-flight consent is exactly the event an incident review wants to find, and
	// it must not vanish with the spent stash.
	if len(h.audit.entries) != 1 || h.audit.entries[0].Action != "oauth_authorize" ||
		h.audit.entries[0].Success == nil || *h.audit.entries[0].Success {
		t.Fatalf("audit entries = %+v, want one failed oauth_authorize", h.audit.entries)
	}
}

// code_challenge and nonce are persisted in VARCHAR(255) columns, so an oversized
// value has to be refused on the first leg — as a redirectable invalid_request the
// client can act on — rather than becoming a 500 at consent time, after the
// single-use stash has been spent and the user has to restart.
func TestAuthorizeBoundsPersistedParameters(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*AuthorizeInput)
	}{
		{"oversized nonce", func(i *AuthorizeInput) { i.Nonce = strings.Repeat("n", 256) }},
		{"oversized state", func(i *AuthorizeInput) { i.State = strings.Repeat("s", 513) }},
		{"short code_challenge", func(i *AuthorizeInput) { i.CodeChallenge = "too-short" }},
		{"oversized code_challenge", func(i *AuthorizeInput) { i.CodeChallenge = strings.Repeat("c", 256) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			input := validAuthorizeInput(t)
			test.mutate(&input)

			_, err := h.service.Authorize(context.Background(), input)

			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Authorize() error = %v, want ErrInvalidRequest", err)
			}
			// Rejected before anything is stashed, so a flood cannot fill the keyspace.
			if h.requests.saveCalls != 0 {
				t.Fatalf("stashed %d requests, want none", h.requests.saveCalls)
			}
		})
	}
}

// Capability scoping rests entirely on this function. Every client type is pinned
// to its registration by ContainsAll. The admin scopes additionally require a
// confidential (third_party) client — a public (first_party) client authenticates
// its token request by PKCE alone, so an intercepted authorization code is one
// barrier short of a credential reaching /admin, where a confidential client has
// two independent barriers. The user scopes carry no type constraint: /user
// operates on the token subject's own record, so even a public client may hold them.
func TestAuthorizeScopeForClientConfinesAdminScopesToConfidentialClientsAndPinsAllToRegistration(t *testing.T) {
	adminGrant := model.StringArray{scope.OpenID, scope.AdminRead, scope.AdminWrite}
	userGrant := model.StringArray{scope.OpenID, scope.UserRead, scope.UserWrite}
	tests := []struct {
		name       string
		clientType model.ClientType
		registered model.StringArray
		requested  []string
		wantErr    bool
	}{
		{
			name:       "confidential client registered for admin",
			clientType: model.ClientTypeThirdParty,
			registered: adminGrant,
			requested:  []string{scope.OpenID, scope.AdminWrite},
		},
		{
			name:       "confidential client registered for user",
			clientType: model.ClientTypeThirdParty,
			registered: userGrant,
			requested:  []string{scope.OpenID, scope.UserRead},
		},
		{
			name:       "confidential client registered for read only cannot request write",
			clientType: model.ClientTypeThirdParty,
			registered: model.StringArray{scope.OpenID, scope.AdminRead},
			requested:  []string{scope.OpenID, scope.AdminWrite},
			wantErr:    true,
		},
		{
			name:       "confidential client not registered for capability scope",
			clientType: model.ClientTypeThirdParty,
			registered: model.StringArray{scope.OpenID, scope.Profile},
			requested:  []string{scope.OpenID, scope.UserRead},
			wantErr:    true,
		},
		{
			// A public client is refused even when its registration grants the scope,
			// because the grant door (adminclient.checkCapabilityScopeGrant) already keeps
			// such a registration from existing — this is the backstop for a registry
			// written around it.
			name:       "public client may never request admin",
			clientType: model.ClientTypeFirstParty,
			registered: adminGrant,
			requested:  []string{scope.OpenID, scope.AdminRead},
			wantErr:    true,
		},
		{
			// The user scopes carry no type constraint: /user operates on the token
			// subject's own record, so even a public client may be granted them.
			name:       "public client registered for user",
			clientType: model.ClientTypeFirstParty,
			registered: userGrant,
			requested:  []string{scope.OpenID, scope.UserRead},
		},
		{
			name:       "public client within its registration",
			clientType: model.ClientTypeFirstParty,
			registered: model.StringArray{scope.OpenID, scope.Profile, scope.Email},
			requested:  []string{scope.OpenID, scope.Profile, scope.Email},
		},
		{
			// The exemption that used to live here: a first-party client could request
			// any supported non-admin scope regardless of its registration, which made
			// the scopes column advisory and any future scope retroactively granted to
			// every existing first-party client. Both client types are now pinned.
			name:       "public client beyond its registration",
			clientType: model.ClientTypeFirstParty,
			registered: model.StringArray{scope.OpenID},
			requested:  []string{scope.OpenID, scope.Profile, scope.Email},
			wantErr:    true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &model.OAuthClient{ClientType: test.clientType, Scopes: test.registered}
			err := authorizeScopeForClient(client, test.requested)
			if test.wantErr && err == nil {
				t.Fatal("authorizeScopeForClient() = nil, want invalid_scope")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("authorizeScopeForClient() error = %v, want nil", err)
			}
		})
	}
}

func TestParseRequestedScopesToleratesWireWhitespace(t *testing.T) {
	accepted := map[string][]string{
		"openid":                     {"openid"},
		"openid profile email":       {"openid", "profile", "email"},
		"openid  profile":            {"openid", "profile"},
		"  openid profile  ":         {"openid", "profile"},
		"email openid":               {"openid", "email"},
		"openid\tprofile":            {"openid", "profile"},
		"openid \t profile \n email": {"openid", "profile", "email"},
	}
	for raw, want := range accepted {
		t.Run("accept/"+raw, func(t *testing.T) {
			got, err := parseRequestedScopes(raw)
			if err != nil {
				t.Fatalf("parseRequestedScopes(%q) error = %v, want nil", raw, err)
			}
			if strings.Join(got, " ") != strings.Join(want, " ") {
				t.Fatalf("parseRequestedScopes(%q) = %v, want %v", raw, got, want)
			}
		})
	}

	// Whitespace tolerance must not become scope tolerance: the set-level rules
	// (openid required, only the three supported values, no duplicates) are the
	// same ones the claim parser enforces.
	for _, raw := range []string{"", "   ", "profile", "profile email", "openid admin", "openid openid"} {
		t.Run("reject/"+raw, func(t *testing.T) {
			if _, err := parseRequestedScopes(raw); err == nil {
				t.Fatalf("parseRequestedScopes(%q) error = nil, want rejection", raw)
			}
		})
	}
}

func TestConsentInfoReturnsVerifiedClientMetadata(t *testing.T) {
	h := newHarness(t)
	authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	info, err := h.service.ConsentInfo(context.Background(), ConsentInfoInput{
		RequestID: authorized.RequestID,
		UserID:    1,
	})
	if err != nil {
		t.Fatalf("ConsentInfo() error = %v", err)
	}
	if info.ClientName != "SAST Link Web" {
		t.Fatalf("ClientName = %q, want %q", info.ClientName, "SAST Link Web")
	}
	if strings.Join(info.Scopes, " ") != strings.Join(authorized.Scopes, " ") {
		t.Fatalf("Scopes = %v, want %v", info.Scopes, authorized.Scopes)
	}
	if info.ExpiresIn <= 0 {
		t.Fatalf("ExpiresIn = %d, want positive", info.ExpiresIn)
	}

	// Peeking must not consume the stash: the user's decision can still be
	// submitted after the page loaded.
	if _, err := h.service.Consent(context.Background(), ConsentInput{
		RequestID: authorized.RequestID,
		Approve:   true,
		UserID:    1,
		ClientIP:  "203.0.113.10",
	}); err != nil {
		t.Fatalf("Consent() after peek error = %v", err)
	}
}

// The consent-info peek is re-validated against the live registration like the
// consent submission itself: an operator's mid-flight scope revocation must not
// leave the page rendering scopes the client can no longer be granted.
func TestConsentInfoRejectsScopeRevokedAfterAuthorize(t *testing.T) {
	h := newHarness(t)
	delegated := h.clients.byClientID[testConfidentialClientID]
	delegated.Scopes = model.StringArray{"openid", scope.AdminRead}

	input := validAuthorizeInput(t)
	input.ClientID = testConfidentialClientID
	input.Scope = "openid " + scope.AdminRead
	authorized, err := h.service.Authorize(context.Background(), input)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	// The operator revokes delegated administration while the consent page is open.
	delegated.Scopes = model.StringArray{"openid"}

	_, err = h.service.ConsentInfo(context.Background(), ConsentInfoInput{
		RequestID: authorized.RequestID,
		UserID:    1,
	})
	requireOAuthError(t, err, ErrorInvalidScope)
}

func TestConsentInfoRejectsUnknownRequest(t *testing.T) {
	h := newHarness(t)
	_, err := h.service.ConsentInfo(context.Background(), ConsentInfoInput{
		RequestID: "ar_doesnotexist",
		UserID:    1,
	})
	if err == nil {
		t.Fatal("ConsentInfo() error = nil, want invalid-request error")
	}
}

// The consent-info peek is throttled per user, not per caller IP: campus egress
// shares one NAT address, so an IP budget would be spent by one student for
// everyone. An authenticated user hammering random request_ids must hit a cap.
func TestConsentInfoThrottlesByUser(t *testing.T) {
	h := newHarness(t)
	h.limiter.result = LimitResult{Allowed: false, RetryAfter: 30 * time.Second}

	_, err := h.service.ConsentInfo(context.Background(), ConsentInfoInput{
		RequestID: "ar_xyz",
		UserID:    7,
	})
	oauthErr := oauthError(t, err, ErrorTemporarilyUnavail)
	if oauthErr.Kind != KindRateLimited || oauthErr.RetryAfter != 30*time.Second {
		t.Fatalf("error = %+v, want a rate-limited error carrying Retry-After", oauthErr)
	}
	calls := h.limiter.callsSnapshot()
	if len(calls) != 1 || calls[0] != "consent_info:user:7" {
		t.Fatalf("limiter calls = %v, want one keyed by user", calls)
	}
}
