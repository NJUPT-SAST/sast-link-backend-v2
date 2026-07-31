package oauthlogin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
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

	States            OAuthStateStore
	RegistrationState RegistrationStateStore
	LoginCodes        LoginCodeStore

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

// Authorize issues an OAuth state and returns the provider page to redirect to.
func (s Service) Authorize(ctx context.Context, input AuthorizeInput) (*AuthorizeResult, error) {
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
	return &AuthorizeResult{AuthorizeURL: client.AuthorizeURL(state), State: state}, nil
}

// Callback validates the provider callback and splits into the login branch or
// the registration branch.
func (s Service) Callback(ctx context.Context, input CallbackInput) (*CallbackResult, error) {
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
	// A state issued for one provider must not be redeemable at another
	// provider's callback, which would let a caller pair a GitHub state with a
	// Lark identity.
	if statePayload.Provider != input.Provider {
		return nil, newError(ErrStateInvalid, "state 与回调 provider 不匹配", nil)
	}

	identity, err := client.Exchange(ctx, input.Code)
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
	user, err := s.Users.FindByID(ctx, existing.UserID)
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

	user, err := s.Users.FindByID(ctx, userID)
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

	client, err := s.Clients.FindActiveByClientID(ctx, s.InternalClientID)
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

	if auditErr := s.audit(ctx, &user.ID, "oauth_login_exchange", "session", true, 0,
		input.ClientIP, input.UserAgent, map[string]any{"user_id": user.ID}); auditErr != nil {
		slog.ErrorContext(ctx, "audit oauth login exchange", "user_id", user.ID, "error", auditErr)
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
