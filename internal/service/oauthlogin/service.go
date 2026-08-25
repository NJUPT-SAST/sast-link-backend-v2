package oauthlogin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/tokenissue"
)

// Token prefixes match the PRD's naming so a value's origin is readable in logs
// and in the frontend URL that carries it.
const (
	loginCodePrefix         = "lc_"
	registrationStatePrefix = "rs_"
	oauthStatePrefix        = "os_"
)

// providerIdentityLimit is the per-user cap on github and lark bindings. V001
// enforces it with a partial unique index; passing it to CreateWithinLimit makes
// the service reject the second binding with a business error instead of relying
// on a constraint violation.
const providerIdentityLimit = 1

// sessionScopes is the scope set granted to an internally issued session. It
// matches the password-login flow, so a third-party login is not more or less
// privileged than the front door.
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

	// Devices registers third-party login sessions in the shared device store
	// (the same Redis adapter the session service uses). A login that goes
	// through GitHub/Lark must count against the per-user 5-device cap like any
	// password login; leaving it out would let a user bypass the cap and would
	// hide the session from the device list entirely. Nil disables the hook
	// (fail-open).
	Devices DeviceStore
	// Blacklist delivers revoked JTIs to Redis after an eviction revoke. Nil
	// skips delivery; the DB revoke is authoritative either way.
	Blacklist TokenBlacklist

	States            OAuthStateStore
	RegistrationState RegistrationStateStore
	LoginCodes        LoginCodeStore

	// AuthorizeLimiter throttles the unauthenticated provider-login endpoints per
	// IP. Each call writes one oauth_state key, so an uncapped endpoint lets
	// anyone fill the keyspace.
	AuthorizeLimiter EndpointLimiter
	// ExchangeLimiter throttles login_code redemption per IP. The endpoint cannot
	// require a session — redeeming the code is how one is obtained — so the cap is
	// what bounds free probing of the code space.
	ExchangeLimiter EndpointLimiter

	Issuer tokenissue.Issuer
	Clock  auth.Clock

	// InternalClientID names the built-in first-party client that owns sessions
	// issued here.
	InternalClientID string

	// AllowedRedirects is the exact-match allow-list of frontend URLs a callback
	// may return the browser to. An open redirect here would let an attacker
	// receive a login_code, so an unlisted value is refused rather than
	// sanitized.
	AllowedRedirects []string
	// DefaultRedirect is used when the caller names no redirect.
	DefaultRedirect string

	StateTTL             time.Duration
	RegistrationStateTTL time.Duration
	LoginCodeTTL         time.Duration
	AccessTTL            time.Duration
	RefreshTTL           time.Duration
}

// checkLimit applies one per-IP endpoint cap.
//
// Fail-open per PRD §6.0: these limiters bound abuse volume, and PostgreSQL plus
// the fail-closed Redis state this flow already consults remain authoritative for
// every decision that matters. Refusing all third-party logins during a Redis
// blip would take the feature down to protect a counter.
//
// An empty clientIP skips the check rather than sharing one bucket: collapsing
// unknown callers into a single key would let one of them lock out the rest.
func (s Service) checkLimit(ctx context.Context, limiter EndpointLimiter, endpoint, clientIP string) error {
	subject := strings.TrimSpace(clientIP)
	if limiter == nil || subject == "" {
		return nil
	}
	result, err := limiter.Allow(ctx, endpoint, "ip:"+subject)
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
	// cannot be used as an unthrottled probe either.
	if err := s.checkLimit(ctx, s.AuthorizeLimiter, "oauth_login", input.ClientIP); err != nil {
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

	state, err := randomToken(oauthStatePrefix)
	if err != nil {
		return nil, newError(ErrInternal, "生成 OAuth state 失败", err)
	}
	payload := StatePayload{Provider: input.Provider, Redirect: redirect}
	if err := s.States.SaveOAuthState(ctx, state, payload, s.stateTTL()); err != nil {
		// Fail-closed: without a stored state the callback could not be
		// validated, so the login must not start.
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
	result, err := s.callback(ctx, input)
	if err != nil {
		// Failed callbacks were previously silent in the audit trail — exactly
		// the events an incident review wants when someone drives a stolen or
		// replayed state at the endpoint. The success legs audit themselves with
		// the resolved user and provider identity.
		s.auditLogin(ctx, nil, input, false, auditErrorCode(err), "")
		return nil, err
	}
	return result, nil
}

func (s Service) callback(ctx context.Context, input CallbackInput) (*CallbackResult, error) {
	// Cancelling on the provider's page is a third outcome, not a failure:
	// GitHub and Lark bounce back with error=access_denied and no code. It
	// skips the code/state demands and the login-CSRF digest binding on
	// purpose — no credential is issued here, so a callback lured onto a
	// cancellation link can show at worst the "已取消登录" page. The state is
	// still consumed when present: one authorization round trip ends with the
	// cancellation, and a later replayed callback finds nothing.
	if input.ProviderError == "access_denied" {
		redirect := s.DefaultRedirect
		if input.State != "" {
			payload, found, err := s.States.ConsumeOAuthState(ctx, input.State)
			if err != nil {
				return nil, newError(ErrDependencyUnavailable, "读取 OAuth state 失败", err)
			}
			// The stored redirect is never empty (resolveRedirect substitutes the
			// default at authorize time), but a spent or forged state reports
			// not-found and falls back to the default. A state issued for the
			// other provider is likewise not adopted: it has no redirect worth
			// honoring here.
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
		return nil, newError(ErrInvalidInput, "code 不能为空", nil)
	}
	if input.State == "" {
		return nil, newError(ErrStateInvalid, "state 不能为空", nil)
	}
	client, err := s.providerClient(input.Provider)
	if err != nil {
		return nil, err
	}

	// The state is consumed before the provider is called, so a replayed
	// callback cannot even reach the exchange.
	statePayload, found, err := s.States.ConsumeOAuthState(ctx, input.State)
	if err != nil {
		return nil, newError(ErrDependencyUnavailable, "读取 OAuth state 失败", err)
	}
	if !found {
		return nil, newError(ErrStateInvalid, "state 无效或已过期", nil)
	}
	// Login CSRF (OAuth 2.0 §10.12): the state alone proves somebody started a
	// login, not that the browser completing it is the one that did. The digest
	// cookie written at authorize time binds the state to that browser; a
	// callback whose cookie is missing or does not match was completed by a
	// browser an attacker lured onto their own authorization URL, and handing it
	// a login_code or registration_state would plant the attacker's provider
	// identity into the victim's session.
	if !stateDigestMatches(input.State, input.StateCookie) {
		return nil, newError(ErrStateInvalid, "state 与发起授权的浏览器不匹配", nil)
	}
	// A state issued for one provider must not be redeemable at another
	// provider's callback, which would let a caller pair a GitHub state with a
	// Lark identity.
	if statePayload.Provider != input.Provider {
		return nil, newError(ErrStateInvalid, "state 与回调 provider 不匹配", nil)
	}

	identity, err := client.Exchange(ctx, input.Code, "")
	if err != nil {
		return nil, providerError(err)
	}

	// Taken from the state rather than re-resolved: Authorize validated it
	// against the allow-list before storing, and SetOneTime's SET NX means an
	// attacker cannot overwrite a victim's pending state to retarget it. The
	// value is never empty, because resolveRedirect substitutes the default at
	// authorize time.
	redirect := statePayload.Redirect

	existing, err := s.Identities.FindByProviderID(ctx, input.Provider, identity.ProviderID)
	if err != nil && !isNotFound(err) {
		return nil, newError(ErrInternal, "查询第三方绑定失败", err)
	}
	if existing == nil {
		return s.registrationBranch(ctx, input, identity, redirect)
	}
	return s.loginBranch(ctx, input, identity, existing, redirect)
}

// loginBranch handles a provider account that is already bound: it refreshes the
// stored credentials and issues a one-time login_code.
func (s Service) loginBranch(
	ctx context.Context,
	input CallbackInput,
	identity *providerIdentity,
	existing *model.Identity,
	redirect string,
) (*CallbackResult, error) {
	user, err := s.Users.FindAuthUserByID(ctx, existing.UserID)
	if err != nil {
		if isNotFound(err) {
			// The binding outlived its user row. Nothing the caller can fix, and
			// it must not mint a login_code for a missing account.
			return nil, newError(ErrUserNotFound, "绑定对应的用户不存在", err)
		}
		return nil, newError(ErrInternal, "查询用户失败", err)
	}
	if user.State == model.UserStateDeleted {
		s.auditLogin(ctx, &user.ID, input, false, ErrUserDeleted.Code, identity.ProviderID)
		return nil, newError(ErrUserDeleted, "账号已注销", nil)
	}

	// Credential refresh is best effort: the user has authenticated, and failing
	// the login because a metadata write failed would be a worse outcome than
	// serving a slightly stale identity_data.
	if updateErr := s.Identities.UpdateProviderCredentials(ctx, existing.ID,
		credentialUpdate(ctx, identity)); updateErr != nil {
		slog.WarnContext(ctx, "refresh identity provider credentials",
			"identity_id", existing.ID, "provider", string(input.Provider), "error", updateErr)
	}

	code, err := randomToken(loginCodePrefix)
	if err != nil {
		return nil, newError(ErrInternal, "生成 login_code 失败", err)
	}
	if err := s.LoginCodes.SaveLoginCode(ctx, code, user.ID, s.loginCodeTTL()); err != nil {
		return nil, newError(ErrDependencyUnavailable, "保存 login_code 失败", err)
	}

	s.auditLogin(ctx, &user.ID, input, true, 0, identity.ProviderID)
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
		return nil, newError(ErrInternal, "生成 registration_state 失败", err)
	}
	payload := RegistrationPayload{
		Provider:     input.Provider,
		ProviderID:   identity.ProviderID,
		IdentityData: identityJSONB(ctx, identity.Data),
		// The original OAuth state is stored alongside so registration can
		// verify the pair. This is the double binding from PRD §4.5: a leaked
		// registration_state is useless without the state the browser carried.
		OAuthState:     input.State,
		AccessToken:    identity.AccessToken,
		RefreshToken:   identity.RefreshToken,
		TokenExpiresAt: identity.TokenExpiresAt,
	}
	if err := s.RegistrationState.SaveRegistrationState(ctx, state, payload, s.registrationStateTTL()); err != nil {
		return nil, newError(ErrDependencyUnavailable, "保存 registration_state 失败", err)
	}

	s.auditLogin(ctx, nil, input, true, 0, identity.ProviderID)
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

// ExchangeCode redeems a one-time login_code for a session.
func (s Service) ExchangeCode(ctx context.Context, input ExchangeCodeInput) (*ExchangeCodeResult, error) {
	result, err := s.exchangeCode(ctx, input)
	if err != nil {
		// The user is unknown on most failure legs (the code may name no one),
		// so the subject stays nil; the action and outcome are what matter.
		if auditErr := s.audit(ctx, nil, "oauth_login_exchange", "session", nil, false, auditErrorCode(err),
			input.ClientIP, input.UserAgent, nil); auditErr != nil {
			logAuditFailure(ctx, "oauth_login_exchange", auditErr)
		}
		return nil, err
	}
	return result, nil
}

func (s Service) exchangeCode(ctx context.Context, input ExchangeCodeInput) (*ExchangeCodeResult, error) {
	// Throttled ahead of the empty-code check: an attacker probing the code space
	// controls the input, so rejecting blanks for free would leave the expensive
	// path — a Redis GetDel per guess — uncapped.
	if err := s.checkLimit(ctx, s.ExchangeLimiter, "oauth_exchange_code", input.ClientIP); err != nil {
		return nil, err
	}
	if input.Code == "" {
		return nil, newError(ErrLoginCodeInvalid, "code 不能为空", nil)
	}
	userID, found, err := s.LoginCodes.ConsumeLoginCode(ctx, input.Code)
	if err != nil {
		return nil, newError(ErrDependencyUnavailable, "读取 login_code 失败", err)
	}
	if !found {
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
	// lives for a minute, and an account closed in that window must not be able
	// to redeem it.
	if user.State == model.UserStateDeleted {
		return nil, newError(ErrUserDeleted, "账号已注销", nil)
	}

	// The built-in client is immutable and cached process-locally, so this costs
	// no DB round trip.
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

	if auditErr := s.audit(ctx, &user.ID, "oauth_login_exchange", "session", nil, true, 0,
		input.ClientIP, input.UserAgent, map[string]any{"user_id": user.ID}); auditErr != nil {
		slog.ErrorContext(ctx, "audit oauth login exchange", "user_id", user.ID, "error", auditErr)
	}
	// A GitHub/Lark login is a session like any password login: register it as
	// a device so it shows up in the device list, counts against the 5-device
	// cap, and can be logged out from the list. The eviction side (revoke the
	// displaced family, drop its record, audit) mirrors the session service.
	// Fail-open: the pair is already committed, and a store outage must not
	// break the login that just succeeded.
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
// per-user cap, exactly like the session service's hook of the same name: the
// eviction is "最多 5 台同时登录" enforcement, and a family whose record
// vanished while its tokens stayed live would become an invisible, unmanageable
// ghost session. Fail-open: the new login already succeeded and an outage must
// not be able to block it.
func (s Service) revokeEvictedDevice(ctx context.Context, userID int64, evicted string, now time.Time, clientIP, userAgent string) {
	if evicted == "" {
		return
	}
	entries, err := s.Tokens.RevokeFamily(ctx, evicted, now)
	if err != nil {
		slog.WarnContext(ctx, "revoke evicted device family failed", "user_id", userID, "device_id", evicted, "error", err)
		return
	}
	if s.Blacklist != nil {
		jtis := make([]string, 0, len(entries))
		for _, entry := range entries {
			// The auth-state cache entry must be deleted so the middleware cannot
			// serve a stale non-revoked state for a token the DB now says revoked.
			if entry.ExpiresAt.Sub(now) <= 0 || strings.TrimSpace(entry.TokenID) == "" {
				continue
			}
			jtis = append(jtis, entry.TokenID)
		}
		if len(jtis) > 0 {
			if err := s.Blacklist.DeleteAuthStates(ctx, jtis); err != nil {
				// The same-transaction outbox row guarantees a worker retry.
				slog.WarnContext(ctx, "deliver auth-state invalidation, outbox worker will retry", "count", len(jtis), "error", err)
			}
		}
	}
	// Drop the displaced record (idempotent). The Redis script already removed
	// the member and usually the Hash; this closes the gap where the Hash
	// delete failed after the script evicted, so no orphan record survives.
	if s.Devices != nil {
		if err := s.Devices.RemoveDevice(ctx, userID, evicted); err != nil {
			slog.WarnContext(ctx, "remove evicted device record failed", "user_id", userID, "device_id", evicted, "error", err)
		}
	}
	if auditErr := s.audit(ctx, &userID, "evict_device", "session", &evicted, true, 0, clientIP, userAgent, map[string]any{"device_id": evicted}); auditErr != nil {
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
