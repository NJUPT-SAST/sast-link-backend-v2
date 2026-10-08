package oauthlogin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/shared"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/tokenissue"
)

// Token prefixes match the PRD's naming so a value's origin is readable in logs
// and in the frontend URL that carries it.
const (
	// pkceMethodS256 mirrors internal/auth's private constant: this flow is
	// S256-only, like the provider surface.
	pkceMethodS256 = "S256"

	loginCodePrefix         = "lc_"
	registrationStatePrefix = "rs_"
	oauthStatePrefix        = "os_"
	// auditSourceAppCode tags the Feishu client JSAPI login-free entrance on
	// oauth_login audit rows, so an incident review can tell which entrance a
	// login came through without a second action name to filter on.
	auditSourceAppCode = "app_code"
)

// providerIdentityLimit is the per-user cap on github and lark bindings;
// passing it to CreateWithinLimit rejects a second binding with a business error
// instead of a constraint violation.
const providerIdentityLimit = 1

// sessionScopes is the scope set granted to an internally issued session,
// matching the password-login flow so a third-party login is not more or less
// privileged.
var sessionScopes = scope.InternalSessionScopes

// Service implements third-party OAuth login, binding and the registration
// hand-off. Dependencies are exported fields assembled in cmd/api, matching the
// session and oauth services.
type Service struct {
	// Providers maps a provider to its outbound client. A provider absent from
	// the map is not enabled in this deployment.
	Providers map[model.LoginMethod]ProviderClient

	Users      UserRepository
	Identities IdentityRepository
	Clients    ClientRepository
	Tokens     TokenRepository
	Audits     AuditRepository

	// Devices registers third-party login sessions in the shared device store (the
	// same Redis adapter the session service uses), so a GitHub/Lark login counts
	// against the per-user 5-device cap and appears in the device list. Nil
	// disables the hook (fail-open).
	Devices DeviceStore
	// Blacklist delivers revoked JTIs to Redis after an eviction revoke. Nil
	// skips delivery; the DB revoke is authoritative either way.
	Blacklist TokenBlacklist

	States            OAuthStateStore
	RegistrationState RegistrationStateStore
	LoginCodes        LoginCodeStore

	// AuthorizeLimiter throttles the unauthenticated provider-login endpoints per
	// IP; each call writes one oauth_state key.
	AuthorizeLimiter EndpointLimiter
	// CallbackLimiter throttles provider callbacks per IP. The callback is a public
	// endpoint that scanners and replay loops hit; without a cap of its own every
	// invalid call still consumes state and writes an audit row, and the authorize
	// budget does not cover it.
	CallbackLimiter EndpointLimiter
	// AppCodeLimiter throttles the Feishu client JSAPI login-free endpoint per
	// IP. The endpoint is unauthenticated and every accepted call spends one
	// provider code exchange, so it needs a cap of its own; it reuses the
	// callback tier's configured rate but a separate bucket, so neither entrance
	// can exhaust the other's budget.
	AppCodeLimiter EndpointLimiter
	// ExchangeLimiter throttles login_code redemption per IP; the endpoint cannot
	// require a session, so the cap bounds probing of the code space.
	ExchangeLimiter EndpointLimiter

	// BindLimiter throttles attaching a provider account to the signed-in caller,
	// keyed on the user rather than the IP: the endpoint is authenticated, so the
	// subject is known, and every accepted call spends one provider code exchange
	// against GitHub or Lark. Without it an authenticated client can drive that
	// exchange in a loop.
	BindLimiter EndpointLimiter

	Issuer tokenissue.Issuer
	Clock  auth.Clock

	// InternalClientID names the built-in first-party client that owns sessions
	// issued here.
	InternalClientID string

	// AllowedRedirects is the exact-match allow-list of frontend URLs a callback
	// may return the browser to; an open redirect would let an attacker receive a
	// login_code, so an unlisted value is refused rather than sanitized.
	AllowedRedirects []string
	// DefaultRedirect is used when the caller names no redirect.
	DefaultRedirect string

	StateTTL             time.Duration
	RegistrationStateTTL time.Duration
	LoginCodeTTL         time.Duration
	AccessTTL            time.Duration
	RefreshTTL           time.Duration
}

// ipSubject namespaces a caller IP for a limiter bucket, or returns "" when the
// IP is unknown. An empty subject skips the check rather than putting every
// unknown caller in one bucket, where one of them could lock out the rest.
func ipSubject(clientIP string) string {
	trimmed := strings.TrimSpace(clientIP)
	if trimmed == "" {
		return ""
	}
	return "ip:" + trimmed
}

// checkLimit applies one endpoint cap.
//
// Fail-open: these limiters bound abuse volume, while PostgreSQL and the
// fail-closed Redis state this flow consults remain authoritative for every
// decision that matters; refusing all third-party logins during a Redis blip
// would take the feature down to protect a counter.
//
// subject is already namespaced by the caller — "ip:…" for the unauthenticated
// endpoints, "user:…" for the authenticated ones — because which identity a
// bucket keys on is a property of the endpoint, not of this helper.
//
// An empty subject skips the check rather than sharing one bucket, so one
// unknown caller cannot lock out the rest.
func (s Service) checkLimit(ctx context.Context, limiter EndpointLimiter, endpoint, subject string) error {
	subject = strings.TrimSpace(subject)
	if limiter == nil || subject == "" {
		return nil
	}
	result, err := limiter.Allow(ctx, endpoint, subject)
	if err != nil {
		slog.WarnContext(ctx, "oauth login limiter unavailable, allowing request",
			"endpoint", endpoint, "error", err)
		return nil
	}
	if !result.Allowed {
		return withRetryAfter(newError(ErrRateLimited, "请求过于频繁", nil), result.RetryAfter)
	}
	return nil
}

// Authorize issues an OAuth state and returns the provider page to redirect to.
func (s Service) Authorize(ctx context.Context, input AuthorizeInput) (*AuthorizeResult, error) {
	// Throttled before the provider is resolved, so a disabled provider's route
	// cannot serve as an unthrottled probe.
	if err := s.checkLimit(ctx, s.AuthorizeLimiter, "oauth_login", ipSubject(input.ClientIP)); err != nil {
		return nil, err
	}
	client, err := s.providerClient(input.Provider)
	if err != nil {
		return nil, err
	}
	redirect, err := s.resolveRedirect(input.Redirect)
	if err != nil {
		return nil, err
	}
	// PKCE (RFC 7636), S256 only, mandatory: the login_code this round trip
	// buys is redeemed by proving the verifier, which never appears in any URL
	// — the callback hands the code through the redirect's query string, and a
	// code leaked that way (Referer, history, logs) is useless without the
	// starting page's secret. A malformed challenge fails here as a fixable
	// client error rather than at redemption time.
	if !auth.IsValidPKCEChallenge(input.CodeChallenge) {
		return nil, newError(ErrInvalidInput, "code_challenge 缺失或格式错误（须为 S256 摘要，43 位 base64url）", nil)
	}
	if input.CodeChallengeMethod != pkceMethodS256 {
		return nil, newError(ErrInvalidInput, "code_challenge_method 仅支持 S256", nil)
	}

	state, err := randomToken(oauthStatePrefix)
	if err != nil {
		return nil, newError(ErrInternal, "生成 OAuth state 失败", err)
	}
	payload := StatePayload{Provider: input.Provider, Redirect: redirect, CodeChallenge: input.CodeChallenge}
	if err := s.States.SaveOAuthState(ctx, state, payload, s.stateTTL()); err != nil {
		// Fail-closed: without a stored state the callback could not be validated,
		// so the login must not start.
		return nil, newError(ErrDependencyUnavailable, "保存 OAuth state 失败", err)
	}
	return &AuthorizeResult{
		AuthorizeURL: client.AuthorizeURL(state),
		State:        state,
		StateDigest:  stateDigest(state),
		StateTTL:     s.stateTTL(),
	}, nil
}

// Callback validates the provider callback and splits into the login branch or
// the registration branch.
func (s Service) Callback(ctx context.Context, input CallbackInput) (*CallbackResult, error) {
	// Throttled before any state is consumed: the point of the cap is to keep an
	// invalid-callback flood from spending state and audit writes.
	if err := s.checkLimit(ctx, s.CallbackLimiter, "oauth_login_callback", ipSubject(input.ClientIP)); err != nil {
		return nil, err
	}
	result, err := s.callback(ctx, input)
	if err != nil {
		// Audit failed callbacks too — they are the events an incident review wants
		// when someone drives a stolen or replayed state at the endpoint; the success
		// legs audit themselves. The stage and reason make a scanner sending no
		// parameters distinguishable from a replayed state or a provider rejection,
		// which one shared business code cannot express. A step that had resolved
		// the account tags it, so its row keeps the user_id it used to lose.
		stage, reason, providerID, userID := failureDetail(err)
		s.auditLogin(ctx, userID, input, false, auditErrorCode(err), providerID, stage, reason)
		return nil, err
	}
	return result, nil
}

func (s Service) callback(ctx context.Context, input CallbackInput) (*CallbackResult, error) {
	client, err := s.providerClient(input.Provider)
	if err != nil {
		return nil, tagCallbackFailure(StageRequestValidation, ReasonProviderDisabled, err)
	}

	// Cancelling on the provider's page is a third outcome, not a failure: GitHub
	// and Lark bounce back with error=access_denied and no code. It skips the
	// code/state demands and the login-CSRF binding on purpose — no credential is
	// issued here, so a cancellation callback is harmless. The state is still
	// consumed when present, so a replayed callback finds nothing.
	if input.ProviderError == "access_denied" {
		redirect := s.DefaultRedirect
		if input.State != "" {
			payload, found, consumeErr := s.States.ConsumeOAuthState(ctx, input.State)
			if consumeErr != nil {
				return nil, tagCallbackFailure(StageState, ReasonStateStoreFailed,
					newError(ErrDependencyUnavailable, "读取 OAuth state 失败", consumeErr))
			}
			// The stored redirect is never empty, but a spent or forged state reports
			// not-found and falls back to the default; a state issued for the other
			// provider is likewise not adopted.
			if found && payload.Provider == input.Provider && payload.Redirect != "" {
				redirect = payload.Redirect
			}
		}
		return &CallbackResult{
			Cancelled: true,
			Provider:  string(input.Provider),
			Redirect:  redirect,
		}, nil
	}
	if input.Code == "" {
		return nil, tagCallbackFailure(StageRequestValidation, ReasonMissingCode,
			newError(ErrInvalidInput, "code 不能为空", nil))
	}
	if input.State == "" {
		return nil, tagCallbackFailure(StageRequestValidation, ReasonMissingState,
			newError(ErrStateInvalid, "state 不能为空", nil))
	}
	// The state is consumed before the provider is called, so a replayed callback
	// cannot even reach the exchange.
	statePayload, found, err := s.States.ConsumeOAuthState(ctx, input.State)
	if err != nil {
		return nil, tagCallbackFailure(StageState, ReasonStateStoreFailed,
			newError(ErrDependencyUnavailable, "读取 OAuth state 失败", err))
	}
	if !found {
		// Display: the default Kind string names the mechanism ("state 无效或已过期"),
		// which a user cannot act on — every cause of a missing state (expired,
		// forged, or consumed by an earlier copy of this same callback) has the
		// same instruction: start the login again.
		return nil, tagCallbackFailure(StageState, ReasonStateNotFound,
			newDisplayError(ErrStateInvalid, "登录已中断，请重新发起登录", nil))
	}
	// Login CSRF (OAuth 2.0 §10.12): the state alone proves somebody started a
	// login, not that the browser completing it is the one that did. The digest
	// cookie binds the state to that browser; a mismatched callback was completed
	// by a browser an attacker lured onto their own authorization URL, and
	// handing it a login_code or registration_state would plant the attacker's
	// provider identity into the victim's session.
	if !stateDigestMatches(input.State, input.StateCookie) {
		reason := ReasonStateCookieMismatch
		if strings.TrimSpace(input.StateCookie) == "" {
			reason = ReasonStateCookieMissing
		}
		return nil, tagCallbackFailure(StageState, reason,
			newDisplayError(ErrStateInvalid, "登录校验失败，请重新发起登录", nil))
	}
	// A state issued for one provider must not be redeemable at another's
	// callback, which would pair a GitHub state with a Lark identity.
	if statePayload.Provider != input.Provider {
		return nil, tagCallbackFailure(StageState, ReasonProviderMismatch,
			newDisplayError(ErrStateInvalid, "登录已中断，请重新发起登录", nil))
	}

	identity, err := client.Exchange(ctx, input.Code, "")
	if err != nil {
		stage, reason, outcome := providerFailureOutcome(err)
		// A provider outage is the one failure whose state is written back:
		// the callback failed on our network leg, not on an answer GitHub or
		// Lark gave, and a retried GET (a browser refresh, the provider page's
		// back-and-authorize) arriving with this state should re-run the whole
		// exchange instead of falling into "state 无效或已过期" — which is what
		// made these outages undiagnosable from the user side. Re-running is
		// safe: the CSRF cookie still binds the state to the browser that started
		// it (the HTTP layer keeps the cookie for exactly this flag), and the code
		// is single-use at the provider, so a retry that finds the code already
		// spent lands on the ordinary restart-the-login path.
		if isRestorableOutcome(outcome) {
			s.restoreStateAfterOutage(ctx, input.State, statePayload)
		}
		return nil, tagCallbackFailure(stage, reason, outcome)
	}

	// Taken from the state rather than re-resolved: Authorize validated it before
	// storing, and the SET NX write means an attacker cannot overwrite a victim's
	// pending state to retarget it.
	redirect := statePayload.Redirect

	existing, err := s.Identities.FindByProviderID(ctx, input.Provider, identity.ProviderID)
	if err != nil && !isNotFound(err) {
		return nil, tagCallbackFailureWithProvider(StageIdentity, ReasonIdentityLookupFailed, identity.ProviderID,
			newError(ErrInternal, "查询第三方绑定失败", err))
	}
	if existing == nil {
		return s.registrationBranch(ctx, input, identity, redirect)
	}
	return s.loginBranch(ctx, input, identity, existing, redirect, statePayload.CodeChallenge)
}

// oauthStateRestoreTTL bounds how long a state is written back after a provider
// outage. Short on purpose: it must cover a user noticing the error page and
// retrying, while keeping the replay window of an outage-restored state far
// below the 10-minute lifetime of a fresh one.
const oauthStateRestoreTTL = 2 * time.Minute

// isRestorableOutcome reports whether a mapped provider failure carries the
// Restorable flag — the same flag the HTTP layer reads to keep the state cookie.
func isRestorableOutcome(outcome error) bool {
	var serviceErr *Error
	return errors.As(outcome, &serviceErr) && serviceErr.Restorable
}

// restoreStateAfterOutage puts a consumed state back so the browser's own
// retry can complete the login. Best-effort: when Redis refuses the write the
// retry simply finds no state and restarts the login, exactly as before.
func (s Service) restoreStateAfterOutage(ctx context.Context, state string, payload StatePayload) {
	ttl := s.stateTTL()
	if ttl > oauthStateRestoreTTL {
		ttl = oauthStateRestoreTTL
	}
	if err := s.States.SaveOAuthState(ctx, state, payload, ttl); err != nil {
		slog.WarnContext(ctx, "restore oauth state after provider outage failed", "error", err)
	}
}

// loginBranch handles a provider account that is already bound: it refreshes the
// stored credentials and issues a one-time login_code.
func (s Service) loginBranch(
	ctx context.Context,
	input CallbackInput,
	identity *providerIdentity,
	existing *model.Identity,
	redirect string,
	challenge string,
) (*CallbackResult, error) {
	user, err := s.Users.FindAuthUserByID(ctx, existing.UserID)
	if err != nil {
		if isNotFound(err) {
			// The binding outlived its user row; nothing the caller can fix, and it must
			// not mint a login_code for a missing account. The binding still names the
			// account, so the failure row keeps its user_id.
			return nil, tagCallbackFailureForUser(StageUser, ReasonUserNotFound, identity.ProviderID, existing.UserID,
				newError(ErrUserNotFound, "绑定对应的用户不存在", err))
		}
		return nil, tagCallbackFailureWithProvider(StageUser, ReasonUserLookupFailed, identity.ProviderID,
			newError(ErrInternal, "查询用户失败", err))
	}
	if user.State == model.UserStateDeleted {
		// Audited by Callback's unified failure path, which reads the tag below, so
		// this case does not write its own row and cannot double-log the event.
		return nil, tagCallbackFailureForUser(StageUser, ReasonUserDeleted, identity.ProviderID, user.ID,
			newError(ErrUserDeleted, "账号已注销", nil))
	}

	// Credential refresh is best effort: failing the login over a metadata write
	// would be worse than serving slightly stale identity_data.
	if updateErr := s.Identities.UpdateProviderCredentials(ctx, existing.ID,
		credentialUpdate(ctx, identity)); updateErr != nil {
		slog.WarnContext(ctx, "refresh identity provider credentials",
			"identity_id", existing.ID, "provider", string(input.Provider), "error", updateErr)
	}

	code, err := randomToken(loginCodePrefix)
	if err != nil {
		return nil, tagCallbackFailureWithProvider(StageSession, ReasonLoginCodeStoreFailed, identity.ProviderID,
			newError(ErrInternal, "生成 login_code 失败", err))
	}
	if err := s.LoginCodes.SaveLoginCode(ctx, code, user.ID, challenge, s.loginCodeTTL()); err != nil {
		return nil, tagCallbackFailureWithProvider(StageSession, ReasonLoginCodeStoreFailed, identity.ProviderID,
			newError(ErrDependencyUnavailable, "保存 login_code 失败", err))
	}

	s.auditLogin(ctx, &user.ID, input, true, 0, identity.ProviderID, "", "")
	return &CallbackResult{Bound: true, LoginCode: code, Redirect: redirect}, nil
}

// registrationBranch parks an unbound provider identity behind a
// registration_state for the caller to complete registration with.
func (s Service) registrationBranch(
	ctx context.Context,
	input CallbackInput,
	identity *providerIdentity,
	redirect string,
) (*CallbackResult, error) {
	state, err := randomToken(registrationStatePrefix)
	if err != nil {
		return nil, tagCallbackFailureWithProvider(StageSession, ReasonRegistrationStateFailed, identity.ProviderID,
			newError(ErrInternal, "生成 registration_state 失败", err))
	}
	payload := RegistrationPayload{
		Provider:     input.Provider,
		ProviderID:   identity.ProviderID,
		IdentityData: identityJSONB(ctx, identity.Data),
		// The original OAuth state is stored alongside so registration can verify the
		// pair — the double binding: a leaked registration_state is useless without
		// the state the browser carried.
		OAuthState:     input.State,
		AccessToken:    identity.AccessToken,
		RefreshToken:   identity.RefreshToken,
		TokenExpiresAt: identity.TokenExpiresAt,
	}
	if err := s.RegistrationState.SaveRegistrationState(ctx, state, payload, s.registrationStateTTL()); err != nil {
		return nil, tagCallbackFailureWithProvider(StageSession, ReasonRegistrationStateFailed, identity.ProviderID,
			newError(ErrDependencyUnavailable, "保存 registration_state 失败", err))
	}

	s.auditLogin(ctx, nil, input, true, 0, identity.ProviderID, "", "")
	return &CallbackResult{
		Bound:             false,
		RegistrationState: state,
		OAuthState:        input.State,
		Provider:          string(input.Provider),
		DisplayName:       identity.DisplayName,
		AvatarURL:         identity.AvatarURL,
		Redirect:          redirect,
	}, nil
}

// AppCodeLogin redeems the pre-authorization code the Feishu client handed
// the embedded web app through the tt.requestAccess / tt.requestAuthCode
// JSAPI: the login-free leg. It reuses the callback flow's branches — a bound
// account gets a login_code, an unbound one gets a registration_state — so the
// two entrances cannot diverge in what they hand the frontend.
func (s Service) AppCodeLogin(ctx context.Context, input AppCodeLoginInput) (*CallbackResult, error) {
	// Throttled before the empty-code check, matching ExchangeCode: the caller
	// controls the input, so a free blank rejection would leave the expensive
	// path — one provider exchange plus Redis writes — uncapped.
	if err := s.checkLimit(ctx, s.AppCodeLimiter, "oauth_login_app_code", ipSubject(input.ClientIP)); err != nil {
		return nil, err
	}
	result, err := s.appCodeLogin(ctx, input)
	if err != nil {
		// Audited through the same shape as a failed callback; the Source tag on
		// the input keeps the row attributable to this entrance.
		stage, reason, providerID, userID := failureDetail(err)
		s.auditLogin(ctx, userID, CallbackInput{
			Provider:  model.LoginMethodLark,
			ClientIP:  input.ClientIP,
			UserAgent: input.UserAgent,
			Source:    auditSourceAppCode,
		}, false, auditErrorCode(err), providerID, stage, reason)
		return nil, err
	}
	return result, nil
}

func (s Service) appCodeLogin(ctx context.Context, input AppCodeLoginInput) (*CallbackResult, error) {
	client, err := s.providerClient(model.LoginMethodLark)
	if err != nil {
		return nil, tagCallbackFailure(StageRequestValidation, ReasonProviderDisabled, err)
	}
	exchanger, ok := client.(AppCodeExchanger)
	if !ok {
		// A Lark provider without the JSAPI leg is a wiring fault, but it is
		// reported the same way as a disabled provider: the caller only needs to
		// know this entrance is not available.
		return nil, tagCallbackFailure(StageRequestValidation, ReasonProviderDisabled,
			newError(ErrInvalidInput, "不支持的第三方登录方式", nil))
	}
	if strings.TrimSpace(input.Code) == "" {
		return nil, tagCallbackFailure(StageRequestValidation, ReasonMissingCode,
			newError(ErrInvalidInput, "code 不能为空", nil))
	}
	// Reject client input before spending the provider's one-time code.
	if !auth.IsValidPKCEChallenge(input.CodeChallenge) {
		return nil, tagCallbackFailure(StageRequestValidation, ReasonInvalidChallenge,
			newError(ErrInvalidInput, "code_challenge 缺失或格式错误（须为 S256 摘要，43 位 base64url）", nil))
	}
	identity, err := exchanger.ExchangeAppCode(ctx, input.Code)
	if err != nil {
		stage, reason, outcome := providerFailureOutcome(err)
		return nil, tagCallbackFailure(stage, reason, outcome)
	}

	// The login-free leg has no state, cookie or redirect. Its validated
	// challenge binds the same login-code issuance as the authorize leg.
	callbackInput := CallbackInput{
		Provider:  model.LoginMethodLark,
		ClientIP:  input.ClientIP,
		UserAgent: input.UserAgent,
		Source:    auditSourceAppCode,
	}
	existing, err := s.Identities.FindByProviderID(ctx, model.LoginMethodLark, identity.ProviderID)
	if err != nil && !isNotFound(err) {
		return nil, tagCallbackFailureWithProvider(StageIdentity, ReasonIdentityLookupFailed, identity.ProviderID,
			newError(ErrInternal, "查询第三方绑定失败", err))
	}
	if existing == nil {
		return s.appCodeRegistrationBranch(ctx, callbackInput, identity)
	}
	return s.loginBranch(ctx, callbackInput, identity, existing, "", input.CodeChallenge)
}

// appCodeRegistrationBranch parks an unbound identity behind a
// registration_state, mirroring registrationBranch for the login-free leg.
//
// The oauth_state half of the double binding is minted here rather than riding
// a provider authorization: the JSAPI flow has no cross-site callback whose
// CSRF a state would bind, so the state's only role is forcing
// POST /auth/register to present both halves of the pair. It is deliberately
// not stored in the OAuthStateStore — nothing will ever consume it there, and
// an unconsumed key would be a never-expiring pseudo attack surface.
func (s Service) appCodeRegistrationBranch(
	ctx context.Context,
	input CallbackInput,
	identity *providerIdentity,
) (*CallbackResult, error) {
	state, err := randomToken(oauthStatePrefix)
	if err != nil {
		return nil, tagCallbackFailureWithProvider(StageSession, ReasonRegistrationStateFailed, identity.ProviderID,
			newError(ErrInternal, "生成 oauth state 失败", err))
	}
	registrationState, err := randomToken(registrationStatePrefix)
	if err != nil {
		return nil, tagCallbackFailureWithProvider(StageSession, ReasonRegistrationStateFailed, identity.ProviderID,
			newError(ErrInternal, "生成 registration_state 失败", err))
	}
	payload := RegistrationPayload{
		Provider:     model.LoginMethodLark,
		ProviderID:   identity.ProviderID,
		IdentityData: identityJSONB(ctx, identity.Data),
		OAuthState:   state,
		// The provider's own credentials are carried through registration so the
		// identity row records them, matching what a callback registration or a
		// /user/identities/* binding would store.
		AccessToken:    identity.AccessToken,
		RefreshToken:   identity.RefreshToken,
		TokenExpiresAt: identity.TokenExpiresAt,
	}
	if err := s.RegistrationState.SaveRegistrationState(ctx, registrationState, payload, s.registrationStateTTL()); err != nil {
		return nil, tagCallbackFailureWithProvider(StageSession, ReasonRegistrationStateFailed, identity.ProviderID,
			newError(ErrDependencyUnavailable, "保存 registration_state 失败", err))
	}

	s.auditLogin(ctx, nil, input, true, 0, identity.ProviderID, "", "")
	return &CallbackResult{
		Bound:             false,
		RegistrationState: registrationState,
		OAuthState:        state,
		Provider:          string(model.LoginMethodLark),
		DisplayName:       identity.DisplayName,
		AvatarURL:         identity.AvatarURL,
	}, nil
}

// ExchangeCode redeems a one-time login_code for a session.
func (s Service) ExchangeCode(ctx context.Context, input ExchangeCodeInput) (*ExchangeCodeResult, error) {
	result, err := s.exchangeCode(ctx, input)
	if err != nil {
		// The user is unknown on most failure legs (the code may name no one), so the
		// subject stays nil; the action and outcome are what matter.
		if auditErr := s.audit(ctx, nil, "oauth_login_exchange", "session", nil, false, auditErrorCode(err), s.InternalClientID,
			input.ClientIP, input.UserAgent, nil); auditErr != nil {
			logAuditFailure(ctx, "oauth_login_exchange", auditErr)
		}
		return nil, err
	}
	return result, nil
}

func (s Service) exchangeCode(ctx context.Context, input ExchangeCodeInput) (*ExchangeCodeResult, error) {
	// Throttled ahead of the empty-code check: probing controls the input, so
	// rejecting blanks for free would leave the expensive Redis GetDel path
	// uncapped.
	if err := s.checkLimit(ctx, s.ExchangeLimiter, "oauth_exchange_code", ipSubject(input.ClientIP)); err != nil {
		return nil, err
	}
	if input.Code == "" {
		return nil, newError(ErrLoginCodeInvalid, "code 不能为空", nil)
	}
	userID, challenge, found, err := s.LoginCodes.ConsumeLoginCode(ctx, input.Code)
	if err != nil {
		return nil, newError(ErrDependencyUnavailable, "读取 login_code 失败", err)
	}
	if !found {
		return nil, newError(ErrLoginCodeInvalid, "login_code 无效或已过期", nil)
	}
	// PKCE redemption (RFC 7636 §4.6): every failure below answers with the
	// login_code-invalid code and copy, because the code was already consumed by
	// the GetDel above — telling a holder of a leaked code that their verifier
	// was "wrong" would hand them a free oracle distinguishing a live code from
	// a spent one, and the burn on failure keeps verification retries from
	// brute-forcing anything.
	if auth.VerifyPKCES256(input.CodeVerifier, challenge, pkceMethodS256) != nil {
		return nil, newError(ErrLoginCodeInvalid, "login_code 无效或已过期", nil)
	}

	user, err := s.Users.FindAuthUserByID(ctx, userID)
	if err != nil {
		if isNotFound(err) {
			return nil, newError(ErrUserNotFound, "用户不存在", err)
		}
		return nil, newError(ErrInternal, "查询用户失败", err)
	}
	// State is re-checked here rather than trusted from the callback: the code
	// lives for a minute, and an account closed in that window must not redeem it.
	if user.State == model.UserStateDeleted {
		return nil, newError(ErrUserDeleted, "账号已注销", nil)
	}

	// The built-in client is immutable and cached process-locally.
	client, err := s.Clients.FindActiveInternalClient(ctx, s.InternalClientID)
	if err != nil {
		return nil, newError(ErrInternal, "查询内置客户端失败", err)
	}
	pair, err := s.Issuer.Issue(tokenissue.Request{
		User:       user,
		Client:     client,
		Scopes:     sessionScopes,
		AccessTTL:  s.accessTTL(),
		RefreshTTL: s.refreshTTL(),
	})
	if err != nil {
		return nil, newError(ErrInternal, "签发 Token 失败", err)
	}
	if err := s.Tokens.CreatePair(ctx, pair.Access, pair.Refresh); err != nil {
		return nil, newError(ErrInternal, "保存 Token 失败", err)
	}

	if auditErr := s.audit(ctx, &user.ID, "oauth_login_exchange", "session", nil, true, 0, s.InternalClientID,
		input.ClientIP, input.UserAgent, map[string]any{"user_id": user.ID}); auditErr != nil {
		slog.ErrorContext(ctx, "audit oauth login exchange", "user_id", user.ID, "error", auditErr)
	}
	// A GitHub/Lark login is a session like any password login: register it as a
	// device so it shows in the device list, counts against the 5-device cap, and
	// can be logged out. Fail-open: the pair is already committed, and a store
	// outage must not break the login that just succeeded.
	if s.Devices != nil {
		// s.now(), not s.Clock.Now(): Clock is not wired in production, and
		// s.now() falls back to the system clock instead of dereferencing nil.
		evicted, err := s.Devices.RegisterDevice(ctx, user.ID, pair.Refresh.FamilyID, input.UserAgent, input.ClientIP, s.now())
		if err != nil {
			slog.WarnContext(ctx, "register device failed", "user_id", user.ID, "error", err)
		}
		s.revokeEvictedDevice(ctx, user.ID, evicted, s.now(), input.ClientIP, input.UserAgent)
	}
	return &ExchangeCodeResult{
		AccessToken:      pair.AccessToken,
		RefreshToken:     pair.RefreshToken,
		TokenType:        BearerTokenType,
		Scope:            pair.ScopeClaim,
		AccessExpiresAt:  pair.Access.ExpiresAt,
		RefreshExpiresAt: pair.Refresh.ExpiresAt,
		User:             user,
	}, nil
}

// revokeEvictedDevice revokes the token family of a device evicted by the
// per-user cap, like the session service's hook of the same name: a family whose
// record vanished while its tokens stayed live would become an invisible,
// unmanageable ghost session. Fail-open: the new login already succeeded.
func (s Service) revokeEvictedDevice(ctx context.Context, userID int64, evicted string, now time.Time, clientIP, userAgent string) {
	if evicted == "" {
		return
	}
	entries, err := s.Tokens.RevokeFamily(ctx, evicted, now)
	if err != nil {
		slog.WarnContext(ctx, "revoke evicted device family failed", "user_id", userID, "device_id", evicted, "error", err)
		return
	}
	// The shared helper applies the same two filters (expired entry, empty JTI) and
	// the same fail-open log; this path used to carry its own copy of both.
	shared.DeliverBlacklist(ctx, s.Blacklist, entries, now)
	// Drop the displaced record (idempotent): the script already removed the
	// member, and this closes the gap where a failed Hash delete would leave an
	// orphan record.
	if s.Devices != nil {
		if err := s.Devices.RemoveDevice(ctx, userID, evicted); err != nil {
			slog.WarnContext(ctx, "remove evicted device record failed", "user_id", userID, "device_id", evicted, "error", err)
		}
	}
	if auditErr := s.audit(ctx, &userID, "evict_device", "session", &evicted, true, 0, s.InternalClientID, clientIP, userAgent, map[string]any{"device_id": evicted}); auditErr != nil {
		slog.ErrorContext(ctx, "audit evict device", "user_id", userID, "device_id", evicted, "error", auditErr)
	}
}

func (s Service) stateTTL() time.Duration {
	if s.StateTTL > 0 {
		return s.StateTTL
	}
	return 10 * time.Minute
}

func (s Service) registrationStateTTL() time.Duration {
	if s.RegistrationStateTTL > 0 {
		return s.RegistrationStateTTL
	}
	return 15 * time.Minute
}

func (s Service) loginCodeTTL() time.Duration {
	if s.LoginCodeTTL > 0 {
		return s.LoginCodeTTL
	}
	return time.Minute
}

func (s Service) accessTTL() time.Duration {
	if s.AccessTTL > 0 {
		return s.AccessTTL
	}
	return time.Hour
}

func (s Service) refreshTTL() time.Duration {
	if s.RefreshTTL > 0 {
		return s.RefreshTTL
	}
	return 30 * 24 * time.Hour
}

// randomToken builds a prefixed 256-bit URL-safe token.
func randomToken(prefix string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// nonEmpty returns a pointer to value, or nil when value is empty, so an absent
// provider credential is stored as SQL NULL rather than an empty string.
func nonEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
