package oauthlogin

import (
	"context"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/provider"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

const BearerTokenType = "Bearer"

// LimitResult is a rate-limit decision.
type LimitResult struct {
	Allowed    bool
	RetryAfter time.Duration
}

// EndpointLimiter throttles one endpoint per subject, mirroring the same port
// the session and oauth services declare.
type EndpointLimiter interface {
	Allow(ctx context.Context, endpoint, subject string) (LimitResult, error)
}

// ProviderClient is one third-party provider; the interface lives here so
// tests can fake a provider without a live endpoint.
type ProviderClient interface {
	// AuthorizeURL builds the provider page to redirect the user to.
	AuthorizeURL(state string) string
	// Exchange turns a callback code into a normalized identity. redirectURI is
	// the exact callback the code was issued against; an empty value uses the
	// provider's configured login callback.
	Exchange(ctx context.Context, code, redirectURI string) (*provider.Identity, error)
}

// StatePayload is the value stored under oauth_state for one login round trip.
//
// Provider is stored rather than inferred from the callback route, so a state
// issued for GitHub cannot be replayed against the Lark callback. Redirect is
// the frontend URL the callback returns the user to.
type StatePayload struct {
	Provider model.LoginMethod `json:"provider"`
	Redirect string            `json:"redirect,omitempty"`
}

// OAuthStateStore holds the short-lived CSRF state for one authorization round
// trip.
//
// Fail-closed: Redis is the only copy, so an unreadable state cannot be treated
// as valid and the user must restart the login.
type OAuthStateStore interface {
	SaveOAuthState(ctx context.Context, state string, payload StatePayload, ttl time.Duration) error
	// ConsumeOAuthState atomically reads and deletes the state, so a replayed
	// callback finds nothing.
	ConsumeOAuthState(ctx context.Context, state string) (payload StatePayload, found bool, err error)
}

// RegistrationPayload is the third-party identity parked for a user who has no
// account yet.
//
// OAuthState is the second half of the double binding: registration must
// present both this registration_state and the original OAuth state, so a
// leaked registration_state alone is not usable.
type RegistrationPayload struct {
	Provider     model.LoginMethod `json:"provider"`
	ProviderID   string            `json:"provider_id"`
	IdentityData model.JSONB       `json:"identity_data"`
	OAuthState   string            `json:"oauth_state"`
	// The provider's own credentials are carried through registration so the
	// identity row records them, matching what a /user/identities/* binding
	// would store.
	AccessToken    string     `json:"access_token,omitempty"`
	RefreshToken   string     `json:"refresh_token,omitempty"`
	TokenExpiresAt *time.Time `json:"token_expires_at,omitempty"`
}

// RegistrationStateStore parks a third-party identity while a new user completes
// registration. Fail-closed, one-time consumption.
type RegistrationStateStore interface {
	SaveRegistrationState(ctx context.Context, state string, payload RegistrationPayload, ttl time.Duration) error
	// ConsumeRegistrationState atomically reads and deletes the payload; the
	// caller compares the stored OAuthState against the submitted one. A mismatch
	// is rejected after the value is gone, so a failed pair is not retryable.
	ConsumeRegistrationState(ctx context.Context, state string) (payload RegistrationPayload, found bool, err error)
}

// LoginCodeStore holds the one-time code the callback hands to the frontend in a
// URL, redeemed for a token pair by POST /oauth/exchange-code.
//
// The callback cannot return tokens directly: it is a 302 to the frontend, and a
// token in the query string would land in browser history and Referer headers.
type LoginCodeStore interface {
	SaveLoginCode(ctx context.Context, code string, userID int64, ttl time.Duration) error
	ConsumeLoginCode(ctx context.Context, code string) (userID int64, found bool, err error)
}

// UserRepository is the subset of user persistence this flow needs.
type UserRepository interface {
	FindByID(ctx context.Context, userID int64) (*model.User, error)
	// FindAuthUserByID returns the scalar columns without the Profile/Identities
	// preloads; login/callback paths only need id, state and the claims fields.
	FindAuthUserByID(ctx context.Context, userID int64) (*model.User, error)
}

// IdentityRepository is the subset of identity persistence this flow needs.
type IdentityRepository interface {
	FindByProviderID(ctx context.Context, provider model.LoginMethod, providerID string) (*model.Identity, error)
	// CreateWithinLimit inserts the binding only while the user holds fewer than
	// limit identities of the provider, checked under a row lock.
	CreateWithinLimit(ctx context.Context, identity *model.Identity, limit int64) error
	// UpdateProviderCredentials refreshes the stored provider tokens and
	// metadata on an existing binding, so a re-login keeps them current.
	UpdateProviderCredentials(ctx context.Context, identityID int64, update repository.IdentityCredentialUpdate) error
}

// ClientRepository resolves the built-in first-party client that owns the
// sessions this flow issues.
type ClientRepository interface {
	FindActiveByClientID(ctx context.Context, clientID string) (*model.OAuthClient, error)
	// FindActiveInternalClient resolves the immutable built-in client, served
	// from a process-local cache; only call it for the internal client ID.
	FindActiveInternalClient(ctx context.Context, clientID string) (*model.OAuthClient, error)
}

// TokenRepository persists an issued session and can revoke a token family;
// RevokeFamily is the same method the session service uses, so an evicted
// device dies the same way a password-login eviction does.
type TokenRepository interface {
	CreatePair(ctx context.Context, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) error
	RevokeFamily(ctx context.Context, familyID string, revokedAt time.Time) ([]model.BlacklistEntry, error)
}

// DeviceStore registers a third-party login session as a device and can drop
// one. The signatures mirror the session service's DeviceStore port so the same
// adapter satisfies both; only registration and removal are needed here, since
// touch/list/logout run through the session service on the shared family IDs.
type DeviceStore interface {
	RegisterDevice(ctx context.Context, userID int64, deviceID, ua, ip string, now time.Time) (evicted string, err error)
	RemoveDevice(ctx context.Context, userID int64, deviceID string) error
}

// TokenBlacklist deletes revoked JTIs' auth-state cache entries so the
// middleware cannot serve a stale non-revoked state. The durable revocation is
// the PostgreSQL row the middleware always checks; this delivery is best-effort
// and must never turn a session into a hard dependency on Redis.
type TokenBlacklist interface {
	DeleteAuthStates(ctx context.Context, jtis []string) error
}

// AuditRepository records the audit trail.
type AuditRepository interface {
	Create(ctx context.Context, entry *model.AuditLog) error
}

// AuthorizeInput starts a login. Redirect is the frontend URL to return to and
// is validated against the configured allow-list.
type AuthorizeInput struct {
	Provider  model.LoginMethod
	Redirect  string
	ClientIP  string
	UserAgent string
}

type AuthorizeResult struct {
	// AuthorizeURL is the provider page to redirect the browser to.
	AuthorizeURL string
	State        string
	// StateDigest is the login-CSRF cookie value pairing the callback with the
	// browser that started this authorization: hex(SHA-256(state)). The callback
	// must present it back, so a state an attacker started cannot complete in a
	// victim's browser.
	StateDigest string
	// StateTTL is how long the state lives; the handler bounds the cookie's
	// Max-Age to it.
	StateTTL time.Duration
}

// CallbackInput is a provider callback; Provider comes from the route, not the
// query, so it cannot be spoofed by the redirect.
type CallbackInput struct {
	Provider  model.LoginMethod
	Code      string
	State     string
	ClientIP  string
	UserAgent string
	// ProviderError is the OAuth error parameter the provider bounced back with
	// (GitHub and Lark send error=access_denied on cancel). Other values are
	// ignored and the callback is judged on code/state alone, so a provider
	// failure string cannot be mistaken for a user action.
	ProviderError string
	// StateCookie is the state cookie the browser sent back; Callback verifies it
	// against the state's digest. Empty means the cookie is missing, which
	// refuses any state that did not originate in this browser.
	StateCookie string
}

// CallbackResult is one of three outcomes, distinguished by which field is set.
//
// A bound account yields LoginCode; an unbound one yields RegistrationState
// plus the profile hints the frontend prefills; a cancellation yields neither
// and only carries Provider + Redirect back to the "已取消登录" page. All carry
// Redirect so the handler knows where to send the browser.
type CallbackResult struct {
	Bound bool

	LoginCode string

	RegistrationState string
	// OAuthState is echoed back so the handler can hand it to the frontend;
	// POST /auth/register needs it alongside RegistrationState, and the page that
	// started the login no longer exists to remember it.
	OAuthState  string
	Provider    string
	DisplayName string
	AvatarURL   string

	// Cancelled reports the user declined the authorization on the provider's
	// page. Not an error: no credentials exist and the state is consumed.
	Cancelled bool

	Redirect string
}

// ExchangeCodeInput redeems a login_code for a session.
type ExchangeCodeInput struct {
	Code      string
	ClientIP  string
	UserAgent string
}

type ExchangeCodeResult struct {
	AccessToken      string
	RefreshToken     string
	TokenType        string
	Scope            string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	User             *model.User
}

// BindInput binds a provider account to the authenticated caller.
//
// RedirectURI is the exact frontend callback the provider code was issued
// against, and must be repeated when exchanging the code; an empty value falls
// back to the provider's configured login callback.
type BindInput struct {
	UserID      int64
	Provider    model.LoginMethod
	Code        string
	RedirectURI string
	ClientIP    string
	UserAgent   string
}

type BindResult struct {
	Identity model.Identity
}
