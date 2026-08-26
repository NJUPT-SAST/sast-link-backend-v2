package oauth

import (
	"context"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// BearerTokenType is the token_type value in every token response.
const BearerTokenType = "Bearer"

// Clock is an alias for auth.Clock to keep this package's API stable.
type Clock = auth.Clock

// LimitResult is a rate-limit decision.
type LimitResult struct {
	Allowed    bool
	RetryAfter time.Duration
}

// EndpointLimiter throttles one endpoint per subject.
type EndpointLimiter interface {
	Allow(ctx context.Context, endpoint, subject string) (LimitResult, error)
}

// TokenBlacklist invalidates the auth-state cache entries for revoked access
// tokens. Revocation is authoritative in PostgreSQL; this clears the short-TTL
// cache so the middleware re-checks the database on the next request.
type TokenBlacklist interface {
	DeleteAuthStates(ctx context.Context, jtis []string) error
}

// AuthorizeRequestPayload is a validated /oauth/authorize request awaiting the
// user's consent decision.
//
// Every field the code will be built from is captured here rather than re-read
// from the consent request, whose echoed parameters are not trusted: a changed
// client, scope or PKCE challenge between legs would let a caller consent to one
// request and mint a code for another.
type AuthorizeRequestPayload struct {
	ClientID string `json:"client_id"`
	// ClientName is captured at authorize time from the verified client record
	// so the consent page can show who is asking without a client lookup or
	// trusting any URL-supplied value.
	ClientName          string   `json:"client_name"`
	RedirectURI         string   `json:"redirect_uri"`
	Scopes              []string `json:"scopes"`
	State               string   `json:"state"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	Nonce               string   `json:"nonce,omitempty"`
}

// AuthorizeRequestStore holds validated authorize requests between the two legs
// of the flow. Fail-closed: Redis is the only copy, so an unreadable request
// cannot be treated as consented and the user must restart.
type AuthorizeRequestStore interface {
	SaveAuthorizeRequest(ctx context.Context, requestID string, payload AuthorizeRequestPayload, ttl time.Duration) error
	// PeekAuthorizeRequest reads a stashed request WITHOUT consuming it, plus its
	// remaining lifetime. Used by the consent page to display verified client
	// metadata before the user decides.
	PeekAuthorizeRequest(ctx context.Context, requestID string) (payload AuthorizeRequestPayload, ttl time.Duration, found bool, err error)
	// ConsumeAuthorizeRequest atomically reads and deletes a stashed request, so a
	// single stash cannot yield two authorization codes.
	ConsumeAuthorizeRequest(ctx context.Context, requestID string) (payload AuthorizeRequestPayload, found bool, err error)
}

// UserRepository reads the account behind an authorization.
type UserRepository interface {
	FindByID(ctx context.Context, userID int64) (*model.User, error)
	// FindAuthUserByID returns the scalar columns without the Profile/Identities
	// preloads; token/UserInfo paths only need the claims and state fields.
	FindAuthUserByID(ctx context.Context, userID int64) (*model.User, error)
}

// ClientRepository resolves OAuth clients.
//
// Only the active-client lookup is needed: every OAuth request authenticates its
// caller, and a deactivated client must not authenticate.
type ClientRepository interface {
	FindActiveByClientID(ctx context.Context, clientID string) (*model.OAuthClient, error)
}

// AuthorizationRepository persists single-use authorization codes and the
// long-lived consent grants behind the authorized-apps list.
type AuthorizationRepository interface {
	// CreateWithGrant persists a new authorization code and records the user's
	// consent for the client in oauth_grants, in one transaction. Consent is the
	// only code-minting path.
	CreateWithGrant(ctx context.Context, authorization *model.OAuthAuthorization) error
	// Consume marks a code used under a row lock. On replay it returns
	// repository.ErrAuthorizationReplayed together with the record, whose family
	// the caller must revoke. The second return is the owning user's token_version
	// snapshot taken inside the consume transaction, which the pair write verifies
	// against so a revocation committing between the two refuses the pair.
	Consume(ctx context.Context, code string, now time.Time) (*model.OAuthAuthorization, int64, error)
	// ListGrantsByUser returns the applications a user has authorized.
	ListGrantsByUser(ctx context.Context, userID int64) ([]repository.OAuthGrant, error)
	// DeleteByUserClient removes every authorization and consent grant a user
	// holds with one client (dropping it from the authorized-apps list and
	// killing any in-flight code).
	DeleteByUserClient(ctx context.Context, userID, clientID int64) error
}

// TokenRepository persists and revokes token metadata.
type TokenRepository interface {
	CreatePair(ctx context.Context, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) error
	// CreatePairWithAudit is CreatePair with the token-issuance audit row written
	// in the same transaction, so the pair and its audit commit atomically.
	CreatePairWithAudit(ctx context.Context, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken, audit *model.AuditLog) error
	// CreatePairWithUserAndClientLock is CreatePairWithAudit inside a transaction
	// that first locks the owning user's and issuing client's rows and refuses
	// (ErrUserStateChanged / ErrClientInactive / ErrClientScopeChanged /
	// ErrNotFound) when the code's state changed: the user's token_version no
	// longer matches the Consume snapshot, the client is inactive, or its scopes no
	// longer contain the pair's. A bulk revocation or client disable/narrowing
	// between consume and write cannot be outlived by the pair.
	CreatePairWithUserAndClientLock(ctx context.Context, userID int64, clientID int64, expectedTokenVersion int64, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken, audit *model.AuditLog) error
	// RotateRefreshToken rotates currentRefreshTokenHash inside familyID and
	// returns the family origin's created_at, so rotation does not advance the ID
	// Token's auth_time: it is read off the sequence-0 row.
	RotateRefreshToken(ctx context.Context, familyID string, currentRefreshTokenHash string, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) (time.Time, error)
	// RotateRefreshTokenWithAudit is RotateRefreshToken with the token-issuance
	// audit row written in the same transaction, so rotation and audit commit
	// atomically.
	RotateRefreshTokenWithAudit(ctx context.Context, familyID string, currentRefreshTokenHash string, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken, audit *model.AuditLog) (time.Time, error)
	// RotateRefreshTokenWithAuditCapped is RotateRefreshTokenWithAudit with a cap
	// on the family's total life measured from its origin: a rotated refresh expiry
	// is clamped to origin+maxLifetime and a family past the cap is revoked, so the
	// client must re-authorize. Zero disables the cap.
	RotateRefreshTokenWithAuditCapped(ctx context.Context, familyID string, currentRefreshTokenHash string, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken, audit *model.AuditLog, maxLifetime time.Duration) (time.Time, error)
	FindRefreshToken(ctx context.Context, tokenHash string) (*model.OAuthRefreshToken, error)
	FindAccessTokenByJTI(ctx context.Context, jti string) (*model.OAuthAccessToken, error)
	RevokeFamily(ctx context.Context, familyID string, revokedAt time.Time) ([]model.BlacklistEntry, error)
	// RevokeUserClientTokens revokes every live token a user holds with one
	// client (removing an application's access).
	RevokeUserClientTokens(ctx context.Context, userID, clientID int64, revokedAt time.Time) ([]model.BlacklistEntry, error)
}

// AuditRepository records audit events.
type AuditRepository interface {
	Create(ctx context.Context, entry *model.AuditLog) error
}

// ProfileRepository reads the display fields backing OIDC profile claims.
type ProfileRepository interface {
	FindPublicCardByUserID(ctx context.Context, userID int64) (*repository.PublicCard, error)
}

// AuthorizeInput is a raw /oauth/authorize request.
type AuthorizeInput struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	ClientIP            string
	UserAgent           string
}

// AuthorizeResult tells the handler where to send the browser.
type AuthorizeResult struct {
	// RequestID identifies the stashed request the consent page must submit.
	RequestID string
	// ExpiresIn is the stash lifetime in seconds.
	ExpiresIn int
	// ClientName is shown on the consent page so the user knows who is asking.
	ClientName string
	// Scopes is the validated scope set being requested.
	Scopes []string
}

// ConsentInput is an authenticated consent decision.
type ConsentInput struct {
	RequestID string
	Approve   bool
	// UserID and UserState come from the verified access token, never from the body.
	UserID    int64
	ClientIP  string
	UserAgent string
}

// ConsentResult carries the URI the browser must be sent to, whether the user
// approved or refused. RFC 6749 §4.1.2.1 requires a refusal to be reported to
// the client as access_denied rather than swallowed here.
type ConsentResult struct {
	RedirectURI string
}

// ConsentInfoInput identifies the pending authorization request whose verified
// client metadata the consent page wants to display.
type ConsentInfoInput struct {
	RequestID string
	// UserID is the authenticated caller; the consent-info peek is rate limited
	// per user, not per IP (campus egress shares one NAT IP).
	UserID int64
}

// ConsentInfoResult is the verified client metadata for one pending request. The
// consent page renders these instead of any client-supplied URL values, so a
// crafted consent link cannot spoof which application is asking.
type ConsentInfoResult struct {
	ClientName string
	Scopes     []string
	ExpiresIn  int
}

// TokenInput is a raw /oauth/token request.
type TokenInput struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	RefreshToken string
	ClientIP     string
	UserAgent    string
}

// TokenResult is an RFC 6749 §5.1 token response.
type TokenResult struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
	Scope        string
	// IDToken is set only for grants carrying the openid scope, which for this
	// service is every grant; it is separate so the handler can omit it.
	IDToken string
}

// RevokeInput is a raw /oauth/revoke request.
type RevokeInput struct {
	Token         string
	TokenTypeHint string
	ClientID      string
	ClientSecret  string
	ClientIP      string
	UserAgent     string
}

// UserInfoInput identifies the subject of a UserInfo request. The fields come
// from the authenticated principal, so this endpoint performs no token parsing
// of its own.
type UserInfoInput struct {
	UserID int64
	Scopes []string
}

// UserInfoResult is the claim set for a UserInfo response. Pointer and omitempty
// fields keep claims outside the granted scopes absent rather than empty, which
// is what OIDC requires.
type UserInfoResult struct {
	Subject           string `json:"sub"`
	Name              string `json:"name,omitempty"`
	Picture           string `json:"picture,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	// Role is this service's own claim rather than an OIDC one, gated by the profile
	// scope and mirroring auth.IDTokenClaims.Role.
	Role          string `json:"role,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
}
