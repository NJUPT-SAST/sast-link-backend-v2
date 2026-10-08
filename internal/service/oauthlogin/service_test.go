package oauthlogin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/provider"
)

// assertDisplayMessage checks that an error carries a user-facing message
// containing want. It is the guard against a message that only reads correctly
// in a log being handed to a browser, and against a genuinely user-facing one
// being replaced by its Kind's generic default.
func assertDisplayMessage(t *testing.T, err error, want string) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want an *oauthlogin.Error", err)
	}
	if !typed.Display {
		t.Fatalf("message %q is not marked for display", typed.Message)
	}
	if !strings.Contains(typed.Message, want) {
		t.Fatalf("message = %q, want it to contain %q", typed.Message, want)
	}
}

func assertKind(t *testing.T, err error, wantKind Kind, wantCode int) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want an *oauthlogin.Error", err)
	}
	if typed.Kind != wantKind {
		t.Fatalf("Kind = %q, want %q (error: %v)", typed.Kind, wantKind, err)
	}
	if typed.Code != wantCode {
		t.Fatalf("Code = %d, want %d (error: %v)", typed.Code, wantCode, err)
	}
}

func activeUser(id int64) *model.User {
	return &model.User{
		ID:         id,
		Role:       model.UserRoleFreshman,
		State:      model.UserStateNJUPTer,
		Name:       "Existing",
		LoginEmail: "existing@sast.fun",
	}
}

func TestAuthorizeStoresStateAndReturnsProviderURL(t *testing.T) {
	service, doubles := newTestService(t)

	result, err := service.Authorize(context.Background(), AuthorizeInput{
		Provider: model.LoginMethodGitHub,

		CodeChallenge: testPKCEChallenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !strings.HasPrefix(result.State, oauthStatePrefix) {
		t.Fatalf("State = %q, want the %q prefix", result.State, oauthStatePrefix)
	}
	if !strings.Contains(result.AuthorizeURL, result.State) {
		t.Fatalf("AuthorizeURL %q does not carry the state", result.AuthorizeURL)
	}
	stored, ok := doubles.States.states[result.State]
	if !ok {
		t.Fatal("state was not persisted")
	}
	// The provider is stored so a state issued for GitHub cannot be redeemed at
	// the Lark callback.
	if stored.Provider != model.LoginMethodGitHub {
		t.Fatalf("stored provider = %q, want github", stored.Provider)
	}
}

func TestAuthorizeRejectsUnknownProvider(t *testing.T) {
	service, _ := newTestService(t)
	// Lark is not in the Providers map for this deployment.
	_, err := service.Authorize(context.Background(), AuthorizeInput{
		Provider: model.LoginMethodLark,

		CodeChallenge: testPKCEChallenge, CodeChallengeMethod: "S256",
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

func TestAuthorizeRejectsRedirectOutsideAllowList(t *testing.T) {
	service, _ := newTestService(t)
	// A prefix rule would admit this; only exact matches are allowed, because
	// the callback hands a login_code to whatever it redirects to.
	_, err := service.Authorize(context.Background(), AuthorizeInput{
		Provider: model.LoginMethodGitHub,
		Redirect: "https://link.sast.fun.evil.test/callback",

		CodeChallenge: testPKCEChallenge, CodeChallengeMethod: "S256",
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

func TestAuthorizeFailsClosedWhenStateStoreIsDown(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.States.saveErr = errStoreDown

	// Without a stored state the callback could not be validated, so the login
	// must not start at all.
	_, err := service.Authorize(context.Background(), AuthorizeInput{
		Provider: model.LoginMethodGitHub,

		CodeChallenge: testPKCEChallenge, CodeChallengeMethod: "S256",
	})
	assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
}

// authorizedState runs Authorize and returns the issued state and its digest,
// so callback tests start from a genuinely stored state — and present the
// matching login-CSRF cookie, which the callback now requires.
func authorizedState(t *testing.T, service Service) (state, digest string) {
	t.Helper()
	result, err := service.Authorize(context.Background(), AuthorizeInput{
		Provider: model.LoginMethodGitHub,

		CodeChallenge: testPKCEChallenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	return result.State, result.StateDigest
}

func TestCallbackBoundUserIssuesLoginCode(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	doubles.Identities.put(&model.Identity{
		UserID: 42, Provider: model.LoginMethodGitHub, ProviderID: "145339646",
	})
	state, stateDigest := authorizedState(t, service)

	result, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "provider-code",
		State:       state,
		StateCookie: stateDigest,
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if !result.Bound {
		t.Fatal("Bound = false, want true for an already-bound account")
	}
	if !strings.HasPrefix(result.LoginCode, loginCodePrefix) {
		t.Fatalf("LoginCode = %q, want the %q prefix", result.LoginCode, loginCodePrefix)
	}
	if result.RegistrationState != "" {
		t.Fatalf("RegistrationState = %q, want empty on the login branch", result.RegistrationState)
	}
	if got := doubles.LoginCodes.codes[result.LoginCode]; got.userID != 42 {
		t.Fatalf("login_code maps to user %d, want 42", got.userID)
	}
	// The stored binding is the challenge the authorize leg carried: a code
	// without it would redeem against any verifier.
	if got := doubles.LoginCodes.codes[result.LoginCode]; got.challenge != testPKCEChallenge {
		t.Fatalf("login_code challenge = %q, want the authorize leg's", got.challenge)
	}
	// A re-login refreshes the stored provider credentials.
	if _, ok := doubles.Identities.updated[1]; !ok {
		t.Fatal("provider credentials were not refreshed on login")
	}
}

func TestCallbackUnboundUserIssuesRegistrationStateBoundToOAuthState(t *testing.T) {
	service, doubles := newTestService(t)
	state, stateDigest := authorizedState(t, service)

	result, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "provider-code",
		State:       state,
		StateCookie: stateDigest,
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if result.Bound {
		t.Fatal("Bound = true, want false for an unbound provider account")
	}
	if !strings.HasPrefix(result.RegistrationState, registrationStatePrefix) {
		t.Fatalf("RegistrationState = %q, want the %q prefix",
			result.RegistrationState, registrationStatePrefix)
	}
	if result.LoginCode != "" {
		t.Fatalf("LoginCode = %q, want empty on the registration branch", result.LoginCode)
	}
	// The profile hints let the frontend prefill the registration form.
	if result.DisplayName != "Ptilopsis" || result.Provider != "github" {
		t.Fatalf("hints = %q/%q, want Ptilopsis/github", result.DisplayName, result.Provider)
	}

	stored, ok := doubles.Registration.states[result.RegistrationState]
	if !ok {
		t.Fatal("registration state was not persisted")
	}
	// PRD §4.5: the parked identity records the OAuth state it came from, so
	// registration can require both halves.
	if stored.OAuthState != state {
		t.Fatalf("stored oauth_state = %q, want %q", stored.OAuthState, state)
	}
	// The result must hand that same state back, or the caller has no way to
	// satisfy the pairing: the state was consumed from Redis and the page that
	// started the login is gone. Returning only the registration_state would
	// make every third-party registration fail with a state mismatch.
	if result.OAuthState != state {
		t.Fatalf("result oauth_state = %q, want %q", result.OAuthState, state)
	}
	if stored.ProviderID != "145339646" {
		t.Fatalf("stored provider_id = %q, want 145339646", stored.ProviderID)
	}
}

func TestCallbackRejectsReplayedState(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	doubles.Identities.put(&model.Identity{
		UserID: 42, Provider: model.LoginMethodGitHub, ProviderID: "145339646",
	})
	state, stateDigest := authorizedState(t, service)

	input := CallbackInput{Provider: model.LoginMethodGitHub, Code: "provider-code", State: state, StateCookie: stateDigest}
	if _, err := service.Callback(context.Background(), input); err != nil {
		t.Fatalf("first Callback: %v", err)
	}
	// The state is consumed on first use, so the replay must not reach the
	// provider exchange at all.
	callsBefore := doubles.GitHub.calls
	_, err := service.Callback(context.Background(), input)
	assertKind(t, err, KindInvalidState, errcode.CodeBadRequest)
	if doubles.GitHub.calls != callsBefore {
		t.Fatal("replayed callback reached the provider exchange")
	}
}

func TestCallbackRejectsStateIssuedForAnotherProvider(t *testing.T) {
	service, doubles := newTestService(t)
	// Enable Lark so the provider lookup succeeds and the mismatch is what
	// rejects the request.
	doubles.GitHub.identity.ProviderID = "145339646"
	service.Providers[model.LoginMethodLark] = &fakeProvider{
		authorizeURL: "https://lark.test/authorize",
		identity:     &provider.Identity{ProviderID: "on_union", Data: map[string]any{}},
	}
	state, stateDigest := authorizedState(t, service) // issued for github

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodLark,
		Code:        "provider-code",
		State:       state,
		StateCookie: stateDigest,
	})
	assertKind(t, err, KindInvalidState, errcode.CodeBadRequest)
}

func TestCallbackRejectsMissingCodeWithoutSpendingState(t *testing.T) {
	service, doubles := newTestService(t)
	state, stateDigest := authorizedState(t, service)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		State:       state,
		StateCookie: stateDigest,
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
	// A rejectable request must not burn the one-time state.
	if _, ok := doubles.States.states[state]; !ok {
		t.Fatal("state was consumed by a request rejected for a missing code")
	}
}

func TestCallbackMapsForeignTenantToBusinessCode(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.GitHub.err = provider.ErrForeignTenant
	state, stateDigest := authorizedState(t, service)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "provider-code",
		State:       state,
		StateCookie: stateDigest,
	})
	assertKind(t, err, KindForbidden, errcode.CodeLarkTenantRequired)
}

func TestCallbackMapsInvalidGrantToRestartableFailure(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.GitHub.err = provider.ErrInvalidGrant
	state, stateDigest := authorizedState(t, service)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "spent",
		State:       state,
		StateCookie: stateDigest,
	})
	// The user's browser carried a stale code; that is a restart, not a 502.
	assertKind(t, err, KindInvalidState, errcode.CodeBadRequest)
	// It shares its Kind with a genuinely expired state, so the message must be
	// user-facing: the state here was valid and correctly bound to the browser,
	// and telling the user otherwise sends them hunting the wrong fault.
	assertDisplayMessage(t, err, "第三方授权码")
}

// A provider outage is the one failure whose consumed state is written back:
// the callback died on our network leg, and a browser retry of the same URL
// should re-run the exchange rather than land on "登录已中断".
func TestCallbackProviderOutageRestoresState(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.GitHub.err = context.DeadlineExceeded
	state, stateDigest := authorizedState(t, service)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "provider-code",
		State:       state,
		StateCookie: stateDigest,
	})
	assertKind(t, err, KindInvalidState, errcode.CodeBadRequest)

	// The state the callback consumed must be back in the store, so the retried
	// GET finds it instead of a not-found.
	payload, found, readErr := doubles.States.ConsumeOAuthState(context.Background(), state)
	if readErr != nil || !found {
		t.Fatalf("state was not restored after the outage: found=%v err=%v", found, readErr)
	}
	if payload.Provider != model.LoginMethodGitHub {
		t.Fatalf("restored payload provider = %q, want github", payload.Provider)
	}
}

// An unexpected provider response is an outage too: same network leg, same
// restore.
func TestCallbackProviderUnavailableRestoresState(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.GitHub.err = provider.ErrUnexpectedResponse
	state, stateDigest := authorizedState(t, service)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "provider-code",
		State:       state,
		StateCookie: stateDigest,
	})
	assertKind(t, err, KindProviderUnavailable, errcode.CodeDependencyUnavailable)

	if _, found, readErr := doubles.States.ConsumeOAuthState(context.Background(), state); readErr != nil || !found {
		t.Fatalf("state was not restored after the outage: found=%v err=%v", found, readErr)
	}
}

// A rejected code is an answer, not an outage: the code is spent at the
// provider, so restoring the state would only invite a retry that can never
// succeed.
func TestCallbackInvalidGrantDoesNotRestoreState(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.GitHub.err = provider.ErrInvalidGrant
	state, stateDigest := authorizedState(t, service)

	_, _ = service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "spent",
		State:       state,
		StateCookie: stateDigest,
	})

	if _, found, _ := doubles.States.ConsumeOAuthState(context.Background(), state); found {
		t.Fatal("state was restored after an invalid grant, want it consumed")
	}
}

// A caller that went away has no browser left to retry the callback; the
// consumed state stays consumed.
func TestCallbackCallerCancelDoesNotRestoreState(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.GitHub.err = context.Canceled
	state, stateDigest := authorizedState(t, service)

	_, _ = service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "provider-code",
		State:       state,
		StateCookie: stateDigest,
	})

	if _, found, _ := doubles.States.ConsumeOAuthState(context.Background(), state); found {
		t.Fatal("state was restored after a caller cancel, want it consumed")
	}
}

// Cancelling on the provider's page is a result, not an error: the callback
// must come back as a cancellation that keeps the frontend's "已取消登录" page,
// not as a parameter failure. The state is consumed on the way out.
func TestCallbackCancellationRejectsDisabledProvider(t *testing.T) {
	service, _ := newTestService(t)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:      model.LoginMethodLark,
		ProviderError: "access_denied",
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

func TestCallbackTreatsAccessDeniedAsCancellation(t *testing.T) {
	service, doubles := newTestService(t)
	state, _ := authorizedState(t, service)

	result, err := service.Callback(context.Background(), CallbackInput{
		Provider:      model.LoginMethodGitHub,
		State:         state,
		ProviderError: "access_denied",
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if !result.Cancelled {
		t.Fatal("Cancelled = false, want the cancellation branch")
	}
	if result.Redirect != "https://link.sast.fun/callback" {
		t.Fatalf("Redirect = %q, want the stored/default redirect", result.Redirect)
	}
	if result.Provider != "github" {
		t.Fatalf("Provider = %q, want github", result.Provider)
	}
	// One authorization round trip ends with the cancellation: a later replayed
	// callback must find the state gone.
	if _, found, _ := doubles.States.ConsumeOAuthState(context.Background(), state); found {
		t.Fatal("state was not consumed by the cancellation")
	}
	// No code was presented, so the provider exchange must never run.
	if doubles.GitHub.calls != 0 {
		t.Fatalf("provider exchange ran %d times for a cancellation", doubles.GitHub.calls)
	}
}

// A cancellation without a usable state (expired, spent, or absent) still lands
// on the frontend callback page via the default redirect.
func TestCallbackCancellationWithoutStateFallsBackToDefaultRedirect(t *testing.T) {
	service, _ := newTestService(t)

	result, err := service.Callback(context.Background(), CallbackInput{
		Provider:      model.LoginMethodGitHub,
		ProviderError: "access_denied",
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if !result.Cancelled || result.Redirect != "https://link.sast.fun/callback" {
		t.Fatalf("Cancelled = %v, Redirect = %q, want cancellation on the default redirect",
			result.Cancelled, result.Redirect)
	}
}

// Even a forged state must not carry a redirect the attacker invented: a
// cancellation presenting a state this deployment never issued falls back to
// the default, and a state issued for the other provider is not adopted either.
func TestCallbackCancellationRejectsForgedAndCrossProviderStates(t *testing.T) {
	service, _ := newTestService(t)

	result, err := service.Callback(context.Background(), CallbackInput{
		Provider:      model.LoginMethodGitHub,
		State:         "os_forged_state_never_issued",
		ProviderError: "access_denied",
	})
	if err != nil {
		t.Fatalf("forged state: %v", err)
	}
	if !result.Cancelled || result.Redirect != "https://link.sast.fun/callback" {
		t.Fatalf("forged state: Cancelled = %v, Redirect = %q, want default", result.Cancelled, result.Redirect)
	}

	// A GitHub callback presenting a state issued for Lark: the stored redirect
	// must not be honored, though the cancellation still lands somewhere safe.
	// Save the state directly through the store — the test service only enables
	// the GitHub provider client, and a cross-provider replay needs no Lark
	// client to exist.
	crossState := "os_cross_provider_state"
	if saveErr := service.States.SaveOAuthState(context.Background(), crossState,
		StatePayload{Provider: model.LoginMethodLark, Redirect: "https://link.sast.fun/lark-route"},
		time.Minute); saveErr != nil {
		t.Fatalf("save lark state: %v", saveErr)
	}
	crossResult, err := service.Callback(context.Background(), CallbackInput{
		Provider:      model.LoginMethodGitHub,
		State:         crossState,
		ProviderError: "access_denied",
	})
	if err != nil {
		t.Fatalf("cross-provider state: %v", err)
	}
	if !crossResult.Cancelled || crossResult.Redirect != "https://link.sast.fun/callback" {
		t.Fatalf("cross-provider: Cancelled = %v, Redirect = %q, want default", crossResult.Cancelled, crossResult.Redirect)
	}
}

// access_denied short-circuits even when a code is present: the decline ends
// the round trip and the provider exchange must never run.
func TestCallbackCancellationWithCodeStillSkipsTheExchange(t *testing.T) {
	service, doubles := newTestService(t)
	state, _ := authorizedState(t, service)

	result, err := service.Callback(context.Background(), CallbackInput{
		Provider:      model.LoginMethodGitHub,
		Code:          "provider-code-issued-before-cancel",
		State:         state,
		ProviderError: "access_denied",
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if !result.Cancelled {
		t.Fatal("Cancelled = false, want the cancellation branch to win over the code")
	}
	if doubles.GitHub.calls != 0 {
		t.Fatalf("provider exchange ran %d times for a cancellation carrying a code", doubles.GitHub.calls)
	}
}

// Only access_denied means a user action. Any other provider error string must
// not be treated as a cancellation — the callback is then judged on its
// code/state alone, and a missing code is still a parameter failure.
func TestCallbackIgnoresNonAccessDeniedProviderErrors(t *testing.T) {
	service, _ := newTestService(t)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:      model.LoginMethodGitHub,
		ProviderError: "temporarily_unavailable",
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

// A provider that accepts the connection and then stalls past the client's I/O
// timeout is a retry, and must not be reported as an expired state.
func TestCallbackMapsProviderTimeoutToRestartableFailure(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.GitHub.err = context.DeadlineExceeded
	state, stateDigest := authorizedState(t, service)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "provider-code",
		State:       state,
		StateCookie: stateDigest,
	})
	assertKind(t, err, KindInvalidState, errcode.CodeBadRequest)
	assertDisplayMessage(t, err, "超时")
}

// A caller that disconnects mid-exchange is not a provider outage and not the
// user's problem to restart, so it keeps the internal (non-display) message.
func TestCallbackMapsCallerCancellationToDependencyFailure(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.GitHub.err = context.Canceled
	state, stateDigest := authorizedState(t, service)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "provider-code",
		State:       state,
		StateCookie: stateDigest,
	})
	assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	var typed *Error
	if errors.As(err, &typed) && typed.Display {
		t.Fatal("a client disconnect must not surface its internal message to the user")
	}
}

// Every failure that reaches the state store keeps its internal message private:
// "读取 OAuth state 失败" names a dependency, not something to show a browser.
func TestStateStoreFailureKeepsItsMessageInternal(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.States.readErr = errors.New("redis down")
	state, stateDigest := authorizedState(t, service)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "provider-code",
		State:       state,
		StateCookie: stateDigest,
	})
	assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
	var typed *Error
	if errors.As(err, &typed) && typed.Display {
		t.Fatalf("internal message %q must not be marked for display", typed.Message)
	}
}

func TestCallbackMapsProviderOutageToBadGatewayKind(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.GitHub.err = provider.ErrUnexpectedResponse
	state, stateDigest := authorizedState(t, service)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "provider-code",
		State:       state,
		StateCookie: stateDigest,
	})
	assertKind(t, err, KindProviderUnavailable, errcode.CodeDependencyUnavailable)
}

func TestCallbackRefusesDeletedAccount(t *testing.T) {
	service, doubles := newTestService(t)
	deleted := activeUser(42)
	deleted.State = model.UserStateDeleted
	doubles.Users.byID[42] = deleted
	doubles.Identities.put(&model.Identity{
		UserID: 42, Provider: model.LoginMethodGitHub, ProviderID: "145339646",
	})
	state, stateDigest := authorizedState(t, service)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "provider-code",
		State:       state,
		StateCookie: stateDigest,
	})
	assertKind(t, err, KindUserDeleted, errcode.CodeAccountDeleted)
	if len(doubles.LoginCodes.codes) != 0 {
		t.Fatal("a login_code was issued for a deleted account")
	}
}

func TestExchangeCodeIssuesSessionAndConsumesCode(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	if err := doubles.LoginCodes.SaveLoginCode(context.Background(), "lc_abc", 42, testPKCEChallenge, 0); err != nil {
		t.Fatalf("seed login code: %v", err)
	}

	result, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "lc_abc", CodeVerifier: testPKCEVerifier})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("ExchangeCode returned an empty token pair")
	}
	if result.TokenType != BearerTokenType {
		t.Fatalf("TokenType = %q, want %q", result.TokenType, BearerTokenType)
	}
	if result.User == nil || result.User.ID != 42 {
		t.Fatalf("User = %+v, want user 42", result.User)
	}
	if doubles.Tokens.pairs != 1 {
		t.Fatalf("persisted pairs = %d, want 1", doubles.Tokens.pairs)
	}
	// Single use: the code is gone.
	if _, ok := doubles.LoginCodes.codes["lc_abc"]; ok {
		t.Fatal("login_code survived the exchange")
	}
}

// A GitHub/Lark login is a session like any password login: it must register
// as a device (same family ID, same Redis store), so it shows up in the device
// list, counts against the 5-device cap and can be logged out from the list.
func TestExchangeCodeRegistersDevice(t *testing.T) {
	service, doubles := newTestService(t)
	devices := &fakeDeviceStore{}
	service.Devices = devices
	doubles.Users.byID[42] = activeUser(42)
	if err := doubles.LoginCodes.SaveLoginCode(context.Background(), "lc_abc", 42, testPKCEChallenge, 0); err != nil {
		t.Fatalf("seed login code: %v", err)
	}

	result, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "lc_abc", CodeVerifier: testPKCEVerifier, ClientIP: "10.0.0.7", UserAgent: "browser/7"})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if len(devices.registrations) != 1 {
		t.Fatalf("registrations = %#v, want exactly one", devices.registrations)
	}
	reg := devices.registrations[0]
	if reg.userID != 42 || reg.ua != "browser/7" || reg.ip != "10.0.0.7" {
		t.Fatalf("registration = %+v, want user 42 with the request ua/ip", reg)
	}
	// The device ID is the family ID of the issued pair (a UUID), so the
	// session and the device record stay one thing.
	if len(reg.deviceID) != 36 || strings.Count(reg.deviceID, "-") != 4 {
		t.Fatalf("device id = %q, want the issued family UUID", reg.deviceID)
	}
	if result.RefreshToken == "" {
		t.Fatal("ExchangeCode returned no refresh token")
	}
}

// The production composition root (cmd/api/runtime.go) wires oauthlogin without a
// Clock, so device registration must fall back to the system clock via now()
// instead of dereferencing the nil interface — that combination previously
// panicked on every third-party login.
func TestExchangeCodeRegistersDeviceWithoutClock(t *testing.T) {
	service, doubles := newTestService(t)
	service.Clock = nil // production leaves Clock unset
	devices := &fakeDeviceStore{}
	service.Devices = devices
	doubles.Users.byID[42] = activeUser(42)
	if err := doubles.LoginCodes.SaveLoginCode(context.Background(), "lc_abc", 42, testPKCEChallenge, 0); err != nil {
		t.Fatalf("seed login code: %v", err)
	}

	if _, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{
		Code: "lc_abc", ClientIP: "10.0.0.7", UserAgent: "browser/7",
		CodeVerifier: testPKCEVerifier,
	}); err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if len(devices.registrations) != 1 {
		t.Fatalf("registrations = %#v, want exactly one with Clock unset", devices.registrations)
	}
}

// Registering a third-party session can displace the oldest device past the
// per-user cap, and the displaced family must be revoked exactly like a
// password-login eviction — otherwise the cap is a display constraint again.
func TestExchangeCodeRevokesEvictedFamily(t *testing.T) {
	service, doubles := newTestService(t)
	devices := &fakeDeviceStore{evicted: "family-oldest"}
	service.Devices = devices
	service.Blacklist = &fakeBlacklist{}
	doubles.Users.byID[42] = activeUser(42)
	if err := doubles.LoginCodes.SaveLoginCode(context.Background(), "lc_abc", 42, testPKCEChallenge, 0); err != nil {
		t.Fatalf("seed login code: %v", err)
	}

	if _, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "lc_abc", CodeVerifier: testPKCEVerifier}); err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if len(doubles.Tokens.revoked) != 1 || doubles.Tokens.revoked[0] != "family-oldest" {
		t.Fatalf("revoked families = %#v, want the displaced family-oldest", doubles.Tokens.revoked)
	}
	if len(devices.removed) != 1 || devices.removed[0] != "family-oldest" {
		t.Fatalf("removed = %#v, want the displaced record cleaned after the revoke", devices.removed)
	}
	// The eviction is a session-killing event; it must be audited, and the
	// resource_id must carry the displaced family just like the session
	// service's evict_device rows, so a third-party-login eviction leaves the
	// same trail as a password-login one.
	var evictedAudit *model.AuditLog
	for i := range doubles.Audits.entries {
		if doubles.Audits.entries[i].Action == "evict_device" {
			evictedAudit = &doubles.Audits.entries[i]
		}
	}
	if evictedAudit == nil || evictedAudit.Success == nil || !*evictedAudit.Success {
		t.Fatalf("evict_device audit = %+v, want a success entry", evictedAudit)
	}
	if evictedAudit.ResourceID == nil || *evictedAudit.ResourceID != "family-oldest" {
		t.Fatalf("evict_device audit resource_id = %v, want the displaced family id", evictedAudit.ResourceID)
	}
	if detail := string(evictedAudit.Detail); !strings.Contains(detail, "family-oldest") {
		t.Fatalf("evict_device audit detail = %s, want the displaced family id", detail)
	}
}

// The device hook must never break the login that just succeeded: a store
// outage or a failed revoke is WARN-only, and the pair is already committed.
func TestExchangeCodeSucceedsWhenDeviceRegistrationFails(t *testing.T) {
	service, doubles := newTestService(t)
	devices := &fakeDeviceStore{registerErr: errors.New("redis down")}
	service.Devices = devices
	doubles.Users.byID[42] = activeUser(42)
	if err := doubles.LoginCodes.SaveLoginCode(context.Background(), "lc_abc", 42, testPKCEChallenge, 0); err != nil {
		t.Fatalf("seed login code: %v", err)
	}

	if _, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "lc_abc", CodeVerifier: testPKCEVerifier}); err != nil {
		t.Fatalf("ExchangeCode returned error, want fail-open session: %v", err)
	}
	if doubles.Tokens.pairs != 1 {
		t.Fatalf("persisted pairs = %d, want 1 despite device-store error", doubles.Tokens.pairs)
	}

	// A device-store error must not lose the eviction: the write may have
	// partially succeeded (set updated, hash delete failed), so the displaced
	// family is still revoked on the error path.
	storeErr := &fakeDeviceStore{registerErr: errors.New("redis down"), evicted: "family-oldest"}
	service.Devices = storeErr
	doubles.LoginCodes.codes["lc_abd"] = loginCodeRecord{userID: 42, challenge: testPKCEChallenge}
	if _, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "lc_abd", CodeVerifier: testPKCEVerifier}); err != nil {
		t.Fatalf("ExchangeCode returned error: %v", err)
	}
	if len(doubles.Tokens.revoked) != 1 || doubles.Tokens.revoked[0] != "family-oldest" {
		t.Fatalf("revoked families = %#v, want eviction still handled on store error", doubles.Tokens.revoked)
	}
}

// The eviction revoke is fail-open: a DB outage WARNs and leaves the new login
// untouched.
func TestExchangeCodeSucceedsWhenEvictedRevokeFails(t *testing.T) {
	service, doubles := newTestService(t)
	service.Devices = &fakeDeviceStore{evicted: "family-oldest"}
	doubles.Tokens.revokeErr = errors.New("db down")
	doubles.Users.byID[42] = activeUser(42)
	if err := doubles.LoginCodes.SaveLoginCode(context.Background(), "lc_abc", 42, testPKCEChallenge, 0); err != nil {
		t.Fatalf("seed login code: %v", err)
	}

	if _, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "lc_abc", CodeVerifier: testPKCEVerifier}); err != nil {
		t.Fatalf("ExchangeCode returned error, want fail-open session: %v", err)
	}
}

func TestExchangeCodeRejectsUnknownCode(t *testing.T) {
	service, _ := newTestService(t)
	_, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "lc_missing", CodeVerifier: testPKCEVerifier})
	assertKind(t, err, KindInvalidToken, errcode.CodeLoginCodeInvalid)
}

func TestExchangeCodeRejectsEmptyCode(t *testing.T) {
	service, _ := newTestService(t)
	_, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{CodeVerifier: testPKCEVerifier})
	assertKind(t, err, KindInvalidToken, errcode.CodeLoginCodeInvalid)
}

func TestExchangeCodeFailsClosedWhenStoreIsDown(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.LoginCodes.readErr = errStoreDown

	// Redis is the only copy of a login_code; a read failure cannot be treated
	// as "valid" or as "expired", so the request is rejected with 503.
	_, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "lc_abc", CodeVerifier: testPKCEVerifier})
	assertKind(t, err, KindDependencyUnavailable, errcode.CodeDependencyUnavailable)
}

func TestExchangeCodeRefusesAccountClosedAfterCodeWasIssued(t *testing.T) {
	service, doubles := newTestService(t)
	deleted := activeUser(42)
	deleted.State = model.UserStateDeleted
	doubles.Users.byID[42] = deleted
	if err := doubles.LoginCodes.SaveLoginCode(context.Background(), "lc_abc", 42, testPKCEChallenge, 0); err != nil {
		t.Fatalf("seed login code: %v", err)
	}

	// The code outlives the account state it was issued under, so state is
	// re-checked at redemption rather than trusted from the callback.
	_, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "lc_abc", CodeVerifier: testPKCEVerifier})
	assertKind(t, err, KindUserDeleted, errcode.CodeAccountDeleted)
	if doubles.Tokens.pairs != 0 {
		t.Fatal("a session was issued for a deleted account")
	}
}

func TestExchangeCodeAuditsTheSession(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	if err := doubles.LoginCodes.SaveLoginCode(context.Background(), "lc_abc", 42, testPKCEChallenge, 0); err != nil {
		t.Fatalf("seed login code: %v", err)
	}
	if _, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "lc_abc", CodeVerifier: testPKCEVerifier}); err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}

	actions := doubles.Audits.actions()
	found := false
	for _, action := range actions {
		if action == "oauth_login_exchange" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit actions = %v, want an oauth_login_exchange entry", actions)
	}
}

func TestAuthorizeThrottlesPerIP(t *testing.T) {
	service, doubles := newTestService(t)
	limiter := &fakeLimiter{result: LimitResult{Allowed: false, RetryAfter: 30 * time.Second}}
	service.AuthorizeLimiter = limiter

	_, err := service.Authorize(context.Background(), AuthorizeInput{
		Provider: model.LoginMethodGitHub,
		ClientIP: "203.0.113.7",

		CodeChallenge: testPKCEChallenge, CodeChallengeMethod: "S256",
	})
	assertKind(t, err, KindRateLimited, errcode.CodeRateLimited)

	var serviceErr *Error
	if !errors.As(err, &serviceErr) {
		t.Fatalf("error type = %T, want *Error", err)
	}
	if serviceErr.RetryAfter != 30*time.Second {
		t.Fatalf("RetryAfter = %v, want 30s", serviceErr.RetryAfter)
	}
	if got, want := limiter.calls[0], "oauth_login:ip:203.0.113.7"; got != want {
		t.Fatalf("limiter call = %q, want %q", got, want)
	}
	// A throttled call must not reach the state store, or the cap would still let
	// the keyspace fill.
	if len(doubles.States.states) != 0 {
		t.Fatalf("states = %d, want none written by a throttled call", len(doubles.States.states))
	}
}

// A disabled provider's route stays registered and answers 40000. The limiter
// must run before that check, otherwise it is an unthrottled probe.
func TestAuthorizeThrottlesBeforeResolvingProvider(t *testing.T) {
	service, _ := newTestService(t)
	limiter := &fakeLimiter{}
	service.AuthorizeLimiter = limiter

	_, err := service.Authorize(context.Background(), AuthorizeInput{
		Provider: model.LoginMethodLark,
		ClientIP: "203.0.113.7",

		CodeChallenge: testPKCEChallenge, CodeChallengeMethod: "S256",
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
	if len(limiter.calls) != 1 {
		t.Fatalf("limiter calls = %v, want the cap applied before the provider check", limiter.calls)
	}
}

func TestAuthorizeAllowsWhenLimiterUnavailable(t *testing.T) {
	service, _ := newTestService(t)
	service.AuthorizeLimiter = &fakeLimiter{err: errors.New("redis unavailable")}

	if _, err := service.Authorize(context.Background(), AuthorizeInput{
		Provider: model.LoginMethodGitHub,
		ClientIP: "203.0.113.7",

		CodeChallenge: testPKCEChallenge, CodeChallengeMethod: "S256",
	}); err != nil {
		t.Fatalf("Authorize with a broken limiter = %v, want fail-open", err)
	}
}

// No client IP means no usable key. Sharing one bucket would let a caller whose
// IP could not be determined lock out every other such caller.
func TestAuthorizeSkipsLimiterWithoutClientIP(t *testing.T) {
	service, _ := newTestService(t)
	limiter := &fakeLimiter{result: LimitResult{Allowed: false}}
	service.AuthorizeLimiter = limiter

	if _, err := service.Authorize(context.Background(), AuthorizeInput{
		Provider: model.LoginMethodGitHub,

		CodeChallenge: testPKCEChallenge, CodeChallengeMethod: "S256",
	}); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if len(limiter.calls) != 0 {
		t.Fatalf("limiter calls = %v, want none without a client IP", limiter.calls)
	}
}

func TestExchangeCodeThrottlesPerIP(t *testing.T) {
	service, doubles := newTestService(t)
	limiter := &fakeLimiter{result: LimitResult{Allowed: false, RetryAfter: 15 * time.Second}}
	service.ExchangeLimiter = limiter
	doubles.Users.byID[42] = activeUser(42)
	if err := doubles.LoginCodes.SaveLoginCode(context.Background(), "lc_abc", 42, testPKCEChallenge, 0); err != nil {
		t.Fatalf("seed login code: %v", err)
	}

	_, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{
		Code:         "lc_abc",
		ClientIP:     "203.0.113.9",
		CodeVerifier: testPKCEVerifier,
	})
	assertKind(t, err, KindRateLimited, errcode.CodeRateLimited)
	if got, want := limiter.calls[0], "oauth_exchange_code:ip:203.0.113.9"; got != want {
		t.Fatalf("limiter call = %q, want %q", got, want)
	}
	// The code must survive a throttled attempt: consuming it would let an
	// attacker burn a victim's live code by tripping the limit.
	if _, _, found, _ := doubles.LoginCodes.ConsumeLoginCode(context.Background(), "lc_abc"); !found {
		t.Fatal("login_code was consumed by a throttled call")
	}
}

// An empty code is the cheapest possible probe, so the cap has to apply to it
// too — otherwise the expensive path stays reachable by alternating inputs.
func TestExchangeCodeThrottlesBeforeRejectingEmptyCode(t *testing.T) {
	service, _ := newTestService(t)
	limiter := &fakeLimiter{}
	service.ExchangeLimiter = limiter

	_, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{ClientIP: "203.0.113.9", CodeVerifier: testPKCEVerifier})
	assertKind(t, err, KindInvalidToken, errcode.CodeLoginCodeInvalid)
	if len(limiter.calls) != 1 {
		t.Fatalf("limiter calls = %v, want the cap applied before the empty-code check", limiter.calls)
	}
}

func TestExchangeCodeAllowsWhenLimiterUnavailable(t *testing.T) {
	service, doubles := newTestService(t)
	service.ExchangeLimiter = &fakeLimiter{err: errors.New("redis unavailable")}
	doubles.Users.byID[42] = activeUser(42)
	if err := doubles.LoginCodes.SaveLoginCode(context.Background(), "lc_abc", 42, testPKCEChallenge, 0); err != nil {
		t.Fatalf("seed login code: %v", err)
	}

	if _, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{
		Code:         "lc_abc",
		ClientIP:     "203.0.113.9",
		CodeVerifier: testPKCEVerifier,
	}); err != nil {
		t.Fatalf("ExchangeCode with a broken limiter = %v, want fail-open", err)
	}
}

// The authorize result carries the login-CSRF cookie value: a digest the
// callback must present back, so a state an attacker started cannot complete
// in a victim's browser (OAuth 2.0 §10.12).
func TestAuthorizeReturnsStateDigestAndTTL(t *testing.T) {
	service, _ := newTestService(t)

	result, err := service.Authorize(context.Background(), AuthorizeInput{
		Provider: model.LoginMethodGitHub,

		CodeChallenge: testPKCEChallenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.StateDigest != stateDigest(result.State) {
		t.Fatalf("StateDigest = %q, want hex(sha256(state)) %q", result.StateDigest, stateDigest(result.State))
	}
	if result.StateTTL <= 0 {
		t.Fatalf("StateTTL = %v, want positive", result.StateTTL)
	}
}

// A callback without the cookie is the login-CSRF attack shape: the browser
// completing the callback did not start the authorization.
func TestCallbackRejectsMissingStateCookie(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	doubles.Identities.put(&model.Identity{
		UserID: 42, Provider: model.LoginMethodGitHub, ProviderID: "145339646",
	})
	state, _ := authorizedState(t, service)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		State:    state,
	})
	assertKind(t, err, KindInvalidState, errcode.CodeBadRequest)
	// The provider exchange must not run for a callback the browser did not start.
	if doubles.GitHub.calls != 0 {
		t.Fatalf("provider exchange ran %d times for a cookie-less callback", doubles.GitHub.calls)
	}
}

// A callback whose cookie does not match the state is refused the same way.
func TestCallbackRejectsMismatchedStateCookie(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	doubles.Identities.put(&model.Identity{
		UserID: 42, Provider: model.LoginMethodGitHub, ProviderID: "145339646",
	})
	state, _ := authorizedState(t, service)

	_, err := service.Callback(context.Background(), CallbackInput{
		Provider:    model.LoginMethodGitHub,
		Code:        "provider-code",
		State:       state,
		StateCookie: stateDigest("some-other-state"),
	})
	assertKind(t, err, KindInvalidState, errcode.CodeBadRequest)
	if doubles.GitHub.calls != 0 {
		t.Fatalf("provider exchange ran %d times for a mismatched cookie", doubles.GitHub.calls)
	}
}

// enableLarkAppCode installs a Lark provider whose JSAPI leg answers with a
// stable union_id identity, and returns it so a test can fail or observe it.
func enableLarkAppCode(service Service) *fakeAppCodeProvider {
	lark := &fakeAppCodeProvider{
		fakeProvider: fakeProvider{authorizeURL: "https://lark.test/authorize"},
		appCodeIdentity: &provider.Identity{
			ProviderID:  "on_union",
			DisplayName: "张三",
			AvatarURL:   "https://lark.test/avatar.png",
			Data:        map[string]any{"union_id": "on_union"},
			AccessToken: "u-token",
		},
	}
	service.Providers[model.LoginMethodLark] = lark
	return lark
}

func TestAppCodeLoginBoundUserIssuesLoginCode(t *testing.T) {
	service, doubles := newTestService(t)
	enableLarkAppCode(service)
	doubles.Users.byID[42] = activeUser(42)
	doubles.Identities.put(&model.Identity{
		UserID: 42, Provider: model.LoginMethodLark, ProviderID: "on_union",
	})

	result, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{Code: "jsapi-code",
		CodeChallenge: testPKCEChallenge,
	})
	if err != nil {
		t.Fatalf("AppCodeLogin: %v", err)
	}
	if !result.Bound {
		t.Fatal("Bound = false, want true for an already-bound account")
	}
	if !strings.HasPrefix(result.LoginCode, loginCodePrefix) {
		t.Fatalf("LoginCode = %q, want the %q prefix", result.LoginCode, loginCodePrefix)
	}
	if got := doubles.LoginCodes.codes[result.LoginCode]; got.userID != 42 {
		t.Fatalf("login_code maps to user %d, want 42", got.userID)
	}
	// The stored binding is the challenge the authorize leg carried: a code
	// without it would redeem against any verifier.
	if got := doubles.LoginCodes.codes[result.LoginCode]; got.challenge != testPKCEChallenge {
		t.Fatalf("login_code challenge = %q, want the authorize leg's", got.challenge)
	}
	// A re-login refreshes the stored provider credentials, same as the callback leg.
	if _, ok := doubles.Identities.updated[1]; !ok {
		t.Fatal("provider credentials were not refreshed on login")
	}
	// No redirect exists on this leg; an accidental non-empty value would send
	// the handler looking for a frontend URL to 302 to.
	if result.Redirect != "" {
		t.Fatalf("Redirect = %q, want empty on the login-free leg", result.Redirect)
	}
}

func TestAppCodeLoginUnboundUserIssuesRegistrationStatePair(t *testing.T) {
	service, doubles := newTestService(t)
	enableLarkAppCode(service)

	result, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{Code: "jsapi-code",
		CodeChallenge: testPKCEChallenge,
	})
	if err != nil {
		t.Fatalf("AppCodeLogin: %v", err)
	}
	if result.Bound {
		t.Fatal("Bound = true, want false for an unbound provider account")
	}
	if !strings.HasPrefix(result.RegistrationState, registrationStatePrefix) {
		t.Fatalf("RegistrationState = %q, want the %q prefix",
			result.RegistrationState, registrationStatePrefix)
	}
	// The oauth_state half is minted here: no provider authorization rode this
	// flow, so nothing else could have produced it.
	if !strings.HasPrefix(result.OAuthState, oauthStatePrefix) {
		t.Fatalf("OAuthState = %q, want the %q prefix", result.OAuthState, oauthStatePrefix)
	}
	if result.Provider != "lark" || result.DisplayName != "张三" {
		t.Fatalf("hints = %q/%q, want lark/张三", result.Provider, result.DisplayName)
	}

	stored, ok := doubles.Registration.states[result.RegistrationState]
	if !ok {
		t.Fatal("registration state was not persisted")
	}
	// POST /auth/register requires both halves; the result must hand back the
	// same oauth_state the payload carries or the pair can never be satisfied.
	if stored.OAuthState != result.OAuthState {
		t.Fatalf("stored oauth_state %q != result oauth_state %q",
			stored.OAuthState, result.OAuthState)
	}
	if stored.ProviderID != "on_union" || stored.Provider != model.LoginMethodLark {
		t.Fatalf("stored = %q/%q, want on_union/lark", stored.ProviderID, stored.Provider)
	}
	// The minted state must not live in the OAuthStateStore: nothing will ever
	// consume it there, and an unconsumed key would read like an attack surface
	// that never expires.
	if _, exists := doubles.States.states[result.OAuthState]; exists {
		t.Fatal("minted oauth_state was persisted in the OAuthStateStore")
	}
}

func TestAppCodeLoginAuditsTheEntrance(t *testing.T) {
	service, doubles := newTestService(t)
	enableLarkAppCode(service)
	doubles.Users.byID[42] = activeUser(42)
	doubles.Identities.put(&model.Identity{
		UserID: 42, Provider: model.LoginMethodLark, ProviderID: "on_union",
	})

	if _, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{Code: "jsapi-code",
		CodeChallenge: testPKCEChallenge,
	}); err != nil {
		t.Fatalf("AppCodeLogin: %v", err)
	}
	found := false
	for _, entry := range doubles.Audits.entries {
		if entry.Action == "oauth_login" && strings.Contains(string(entry.Detail), `"source":"app_code"`) {
			found = true
		}
	}
	if !found {
		t.Fatal("no oauth_login audit row tagged source=app_code")
	}
}

func TestAppCodeLoginRejectsEmptyCode(t *testing.T) {
	service, _ := newTestService(t)
	lark := enableLarkAppCode(service)

	_, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{
		CodeChallenge: testPKCEChallenge,
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
	if lark.appCodeCalls != 0 {
		t.Fatalf("provider exchange ran %d times for an empty code", lark.appCodeCalls)
	}
}

func TestAppCodeLoginRejectsDisabledProvider(t *testing.T) {
	service, _ := newTestService(t) // Lark not installed

	_, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{Code: "jsapi-code",
		CodeChallenge: testPKCEChallenge,
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

// A Lark registration without the JSAPI leg is a wiring fault; it must surface
// as the same "entrance unavailable" outcome rather than panic on the
// interface assertion.
func TestAppCodeLoginRejectsProviderWithoutAppCodeLeg(t *testing.T) {
	service, _ := newTestService(t)
	service.Providers[model.LoginMethodLark] = &fakeProvider{
		authorizeURL: "https://lark.test/authorize",
		identity:     &provider.Identity{ProviderID: "on_union", Data: map[string]any{}},
	}

	_, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{Code: "jsapi-code",
		CodeChallenge: testPKCEChallenge,
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

func TestAppCodeLoginMapsSpentCodeToRestartableFailure(t *testing.T) {
	service, _ := newTestService(t)
	lark := enableLarkAppCode(service)
	lark.appCodeErr = provider.ErrInvalidGrant

	_, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{Code: "spent",
		CodeChallenge: testPKCEChallenge,
	})
	assertKind(t, err, KindInvalidState, errcode.CodeBadRequest)
	assertDisplayMessage(t, err, "第三方授权码")
}

func TestAppCodeLoginMapsForeignTenantToBusinessCode(t *testing.T) {
	service, _ := newTestService(t)
	lark := enableLarkAppCode(service)
	lark.appCodeErr = provider.ErrForeignTenant

	_, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{Code: "jsapi-code",
		CodeChallenge: testPKCEChallenge,
	})
	assertKind(t, err, KindForbidden, errcode.CodeLarkTenantRequired)
}

// The failure path synthesizes its own CallbackInput — the one place the
// source tag could be silently dropped later — so a failure row's shape needs
// its own pin: the entrance tag plus the step/cause pair, same as a failed
// callback.
func TestAppCodeLoginFailureAuditsTheEntrance(t *testing.T) {
	service, doubles := newTestService(t)
	lark := enableLarkAppCode(service)
	lark.appCodeErr = provider.ErrInvalidGrant

	if _, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{Code: "spent",
		CodeChallenge: testPKCEChallenge,
	}); err == nil {
		t.Fatal("AppCodeLogin() error = nil, want a rejection")
	}
	entry := lastAuditEntry(t, doubles.Audits)
	if entry.Success == nil || *entry.Success {
		t.Fatal("failed login did not write success=false")
	}
	if got := detailString(t, entry, "source"); got != auditSourceAppCode {
		t.Fatalf("source = %q, want %q", got, auditSourceAppCode)
	}
	if got := detailString(t, entry, "failure_stage"); got != StageProvider {
		t.Fatalf("failure_stage = %q, want %q", got, StageProvider)
	}
	if got := detailString(t, entry, "failure_reason"); got != ReasonProviderInvalidGrant {
		t.Fatalf("failure_reason = %q, want %q", got, ReasonProviderInvalidGrant)
	}
}

func TestAppCodeLoginThrottlesPerIP(t *testing.T) {
	service, _ := newTestService(t)
	lark := enableLarkAppCode(service)
	limiter := &fakeLimiter{result: LimitResult{Allowed: false, RetryAfter: 15 * time.Second}}
	service.AppCodeLimiter = limiter

	_, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{
		Code:     "jsapi-code",
		ClientIP: "203.0.113.9",

		CodeChallenge: testPKCEChallenge,
	})
	assertKind(t, err, KindRateLimited, errcode.CodeRateLimited)
	if got, want := limiter.calls[0], "oauth_login_app_code:ip:203.0.113.9"; got != want {
		t.Fatalf("limiter call = %q, want %q", got, want)
	}
	if lark.appCodeCalls != 0 {
		t.Fatal("throttled call reached the provider exchange")
	}
}

// An empty code is the cheapest possible probe, so the cap has to apply to it
// too — the expensive path is one provider exchange plus Redis writes.
func TestAppCodeLoginThrottlesBeforeRejectingEmptyCode(t *testing.T) {
	service, _ := newTestService(t)
	limiter := &fakeLimiter{}
	service.AppCodeLimiter = limiter

	_, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{ClientIP: "203.0.113.9",
		CodeChallenge: testPKCEChallenge,
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
	if len(limiter.calls) != 1 {
		t.Fatalf("limiter saw %d calls, want it consulted before the empty-code rejection", len(limiter.calls))
	}
}

// --- PKCE binding on the login_code exchange leg ---

// The authorize leg refuses to start without a well-formed S256 challenge: a
// login_code minted without a binding would redeem against any bearer, which is
// exactly the exposure the binding exists to close.
func TestAuthorizeRequiresSizedS256Challenge(t *testing.T) {
	service, _ := newTestService(t)

	cases := []struct {
		name    string
		input   AuthorizeInput
		wantMsg string
	}{
		{"missing challenge", AuthorizeInput{Provider: model.LoginMethodGitHub}, "code_challenge"},
		{"short challenge", AuthorizeInput{Provider: model.LoginMethodGitHub, CodeChallenge: "tooshort", CodeChallengeMethod: "S256"}, "code_challenge"},
		{"plain method", AuthorizeInput{Provider: model.LoginMethodGitHub, CodeChallenge: testPKCEChallenge, CodeChallengeMethod: "plain"}, "S256"},
		{"missing method", AuthorizeInput{Provider: model.LoginMethodGitHub, CodeChallenge: testPKCEChallenge}, "S256"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.Authorize(context.Background(), test.input)
			if err == nil || !strings.Contains(err.Error(), test.wantMsg) {
				t.Fatalf("Authorize() error = %v, want a refusal naming %q", err, test.wantMsg)
			}
		})
	}
}

// The exchange leg refuses a wrong or missing verifier with the same code and
// copy as an unknown login_code, and the GetDel has already burned the code:
// a holder of a leaked code gets no oracle and no retry surface.
func TestExchangeCodeWrongVerifierBurnsTheCode(t *testing.T) {
	for name, verifier := range map[string]string{"wrong": strings.Repeat("w", 43), "missing": "", "short": "short"} {
		t.Run(name, func(t *testing.T) {
			service, doubles := newTestService(t)
			doubles.Users.byID[42] = activeUser(42)
			if err := doubles.LoginCodes.SaveLoginCode(context.Background(), "lc_abc", 42, testPKCEChallenge, 0); err != nil {
				t.Fatal(err)
			}
			_, err := service.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "lc_abc", CodeVerifier: verifier})
			assertKind(t, err, KindInvalidToken, errcode.CodeLoginCodeInvalid)
			if _, ok := doubles.LoginCodes.codes["lc_abc"]; ok {
				t.Fatal("login_code survived failed verification")
			}
			// The correct proof must not resurrect a code burned by this attempt.
			_, err = service.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "lc_abc", CodeVerifier: testPKCEVerifier})
			assertKind(t, err, KindInvalidToken, errcode.CodeLoginCodeInvalid)
			if doubles.Tokens.pairs != 0 {
				t.Fatalf("persisted pairs=%d", doubles.Tokens.pairs)
			}
		})
	}
}

// The Feishu embedded-page entrance carries the same binding: its login_code
// is bound to the challenge the page posted.
func TestAppCodeLoginRequiresChallengeAndBindsIt(t *testing.T) {
	service, doubles := newTestService(t)
	enableLarkAppCode(service)
	doubles.Identities.put(&model.Identity{
		UserID: 42, Provider: model.LoginMethodLark, ProviderID: "on_union",
	})
	doubles.Users.byID[42] = activeUser(42)

	if _, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{Code: "jsapi"}); err == nil ||
		!strings.Contains(err.Error(), "code_challenge") {
		t.Fatalf("AppCodeLogin() error = %v, want a refusal naming code_challenge", err)
	}

	result, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{Code: "jsapi", CodeChallenge: testPKCEChallenge})
	if err != nil {
		t.Fatalf("AppCodeLogin: %v", err)
	}
	if record, ok := doubles.LoginCodes.codes[result.LoginCode]; !ok || record.challenge != testPKCEChallenge {
		t.Fatalf("login_code challenge = %+v, want the posted binding", record)
	}
}
