package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

const principalContextKey = "principal"

// Principal is the authenticated user context derived from a validated JWT.
type Principal struct {
	UserID int64
	JTI    string
	Role   string
	State  string
	Scopes []string
	// ClientID is the azp claim: the client this token was issued to. Empty means a
	// first-party session token.
	ClientID  string
	ExpiresAt time.Time
}

type JWTVerifier interface {
	VerifyAccessToken(token string) (*auth.TokenClaims, error)
	// VerifyExpiredAccessToken verifies everything VerifyAccessToken does except
	// the expiry, returning an expired token's claims.
	VerifyExpiredAccessToken(token string) (*auth.TokenClaims, error)
}

// AuthStateCache is the short-TTL Redis cache for the per-token auth state. A
// cache hit lets an authenticated request skip the per-request DB query; the
// revocation paths write a short-lived tombstone so a revoked token's cached
// state can never admit it. Fail-open: a cache error falls back to the database,
// never rejects.
type AuthStateCache interface {
	GetAuthState(ctx context.Context, jti string) ([]byte, bool, error)
	PutAuthState(ctx context.Context, jti string, data []byte, ttl time.Duration) error
}

// AccessAuthStateRepository reads the DB-authoritative access-token state.
type AccessAuthStateRepository interface {
	FindAccessAuthStateByJTI(ctx context.Context, jti string) (*repository.AccessAuthState, error)
}

type Authenticator struct {
	JWT    JWTVerifier
	Tokens AccessAuthStateRepository
	Clock  auth.Clock
	// AuthStateCache is the per-token auth-state cache. Nil disables caching
	// (every request hits the database), which is also the failure fallback.
	AuthStateCache AuthStateCache
	// AuthStateTTL bounds how long a cached entry lives without an explicit
	// revocation invalidating it.
	AuthStateTTL time.Duration
	// InternalClientID is the built-in first-party client. Only tokens issued to it
	// may authenticate on the internal API.
	//
	// Every access token carries this service as its audience, so the audience cannot
	// tell a first-party session from a third-party grant; the azp claim is pinned to
	// this field, or an openid-only grant would act as a full session credential
	// (account takeover).
	//
	// Required. An empty value rejects every request rather than admitting all of
	// them, so a deployment that forgets to set it fails loudly instead of silently
	// dropping the check.
	InternalClientID string
}

func (a Authenticator) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, err := a.Authenticate(c.Request.Context(), c.GetHeader("Authorization"))
		if err != nil {
			response.Error(c, err)
			c.Abort()
			return
		}
		c.Set(principalContextKey, principal)
		c.Next()
	}
}

// Authenticate validates an Authorization header for the internal API and returns
// its principal. Tokens issued to any client other than InternalClientID are
// rejected.
//
// Exported so endpoints with a non-standard error format reuse the same validation
// instead of reimplementing it. The returned error is a *response.BusinessError, so
// a caller that wants the standard envelope can pass it to response.Error.
func (a Authenticator) Authenticate(ctx context.Context, header string) (Principal, error) {
	principal, err := a.authenticate(ctx, header)
	if err != nil {
		return Principal{}, err
	}
	if err := a.requireInternalClient(principal); err != nil {
		return Principal{}, err
	}
	return principal, nil
}

// AuthenticateAnyClient validates a token regardless of which client it was issued
// to. It is for OAuth-facing endpoints that must serve third-party tokens by
// design (OIDC UserInfo is the only one); it must never back an internal
// endpoint, where a third-party token acting as a session credential is account
// takeover.
func (a Authenticator) AuthenticateAnyClient(ctx context.Context, header string) (Principal, error) {
	return a.authenticate(ctx, header)
}

// requireScopedAuth is the middleware factory behind RequireAdminAuth and
// RequireUserAuth: authenticate the header, put the principal in the context, or
// answer in the standard envelope.
func (a Authenticator) requireScopedAuth(
	authenticate func(ctx context.Context, header string) (Principal, error),
) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, err := authenticate(c.Request.Context(), c.GetHeader("Authorization"))
		if err != nil {
			response.Error(c, err)
			c.Abort()
			return
		}
		c.Set(principalContextKey, principal)
		c.Next()
	}
}

// RequireAdminAuth authenticates the /admin endpoints, admitting an internal
// console token or any token that carries an admin scope.
//
// A separate gate rather than a relaxation of RequireAuth keeps the default
// fail-closed: every route that does not opt in keeps rejecting third-party
// tokens. Pair it with RequireDelegatedScope — this method proves *which client*
// may speak for an administrator, not *what* it may do.
func (a Authenticator) RequireAdminAuth() gin.HandlerFunc {
	return a.requireScopedAuth(a.AuthenticateAdminDelegated)
}

// AuthenticateAdminDelegated validates an Authorization header for the admin API.
// It accepts an internal-client token unconditionally, and any other token only
// when it carries an admin scope; every other client is rejected exactly as
// Authenticate would reject it.
//
// The admin scope is not self-asserted: it can only appear if the console granted
// the registration that scope, which also refuses the capability scopes for
// first_party clients, so "this token has admin:read" already proves an
// administrator granted it. The subject's role is read from the database row on
// every request, so a demotion cuts the capability off on the next request; this
// method proves *which client may speak*, never that the subject may act. Pair it
// with RequireDelegatedScope for what the credential may do.
func (a Authenticator) AuthenticateAdminDelegated(ctx context.Context, header string) (Principal, error) {
	return a.authenticateScoped(ctx, header,
		func(p Principal) bool { return scope.ContainsAdmin(p.Scopes) },
		"该 Access Token 未携带管理接口所需的 scope")
}

// RequireUserAuth authenticates the /user endpoints, admitting an internal
// console token or any other token that carries a self-service scope.
//
// A separate gate rather than a relaxation of RequireAuth keeps the default
// fail-closed: every route that does not opt in keeps rejecting non-console
// tokens. Pair it with RequireDelegatedScope — this method proves *which client*
// may act on a user's own record, not *what* it may do.
func (a Authenticator) RequireUserAuth() gin.HandlerFunc {
	return a.requireScopedAuth(a.AuthenticateUserScoped)
}

// AuthenticateUserScoped validates an Authorization header for the /user endpoints.
// It accepts an internal-client token unconditionally, and any other token only
// when it carries a self-service scope; every other client is rejected exactly as
// Authenticate would reject it.
//
// The user scope is not self-asserted: it can only appear if the console granted
// the registration that scope at authorize time. No client-type lookup happens on
// the request path — every /user endpoint operates on the token subject's own
// record, so an application holding a user scope is never a look-up-anyone
// credential.
func (a Authenticator) AuthenticateUserScoped(ctx context.Context, header string) (Principal, error) {
	return a.authenticateScoped(ctx, header,
		func(p Principal) bool { return scope.ContainsUser(p.Scopes) },
		"该 Access Token 未携带访问用户接口所需的 scope")
}

// RequireUserLogoutAuth authenticates the logout endpoint, tolerating an
// expired access token. Everything else follows the /user scoped gate: the
// console session is exempt, any other client must carry a self-service scope.
func (a Authenticator) RequireUserLogoutAuth() gin.HandlerFunc {
	return a.requireScopedAuth(a.AuthenticateUserLogout)
}

// AuthenticateUserLogout validates the logout request, tolerating an expired
// access token. A fresh token runs the full chain exactly as
// AuthenticateUserScoped does; an expired one is re-parsed through the RFC 7009
// expired-token path and admitted on its claims alone.
//
// Expire is forgiven only here: an expired access token still names a live
// refresh family, so a stale tab can end its session without re-authenticating.
// Signature, issuer, audience and the required claims stay verified — only the
// clock is relaxed, so an attacker-chosen jti cannot revoke an arbitrary family —
// and the service layer confirms the jti resolves to a real token row before it
// touches a family.
func (a Authenticator) AuthenticateUserLogout(ctx context.Context, header string) (Principal, error) {
	token, ok := strictBearerToken(header)
	if !ok {
		return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeUnauthenticated, "未登录（缺少或无效 Authorization Header）")
	}
	if a.JWT == nil {
		return Principal{}, backendError()
	}
	_, err := a.JWT.VerifyAccessToken(token)
	if errors.Is(err, auth.ErrExpiredToken) {
		expiredClaims, expiredErr := a.JWT.VerifyExpiredAccessToken(token)
		if expiredErr != nil {
			return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenInvalid, "Access Token 无效或已被撤销")
		}
		userID, parseErr := strconv.ParseInt(expiredClaims.Subject, 10, 64)
		if parseErr != nil || userID <= 0 || strings.TrimSpace(expiredClaims.ID) == "" || expiredClaims.ExpiresAt == nil {
			return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenInvalid, "Access Token 无效或已被撤销")
		}
		scopes, parseErr := scope.ParseClaim(expiredClaims.Scope)
		if parseErr != nil {
			return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenInvalid, "Access Token 无效或已被撤销")
		}
		return a.applyScopedPolicy(principalFromClaims(expiredClaims, userID, scopes, nil),
			func(p Principal) bool { return scope.ContainsUser(p.Scopes) },
			"该 Access Token 未携带访问用户接口所需的 scope")
	}
	if err != nil {
		return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenInvalid, "Access Token 无效或已被撤销")
	}
	return a.AuthenticateUserScoped(ctx, header)
}

// authenticateScoped is the shared core of the two scoped-surface authenticators:
// validate the token, exempt the console session unconditionally, and otherwise
// require the capability predicate to pass. A missing InternalClientID fails
// closed before the scoped branch.
func (a Authenticator) authenticateScoped(
	ctx context.Context,
	header string,
	carriesCapability func(Principal) bool,
	deniedMessage string,
) (Principal, error) {
	principal, err := a.authenticate(ctx, header)
	if err != nil {
		return Principal{}, err
	}
	return a.applyScopedPolicy(principal, carriesCapability, deniedMessage)
}

// applyScopedPolicy decides whether an already-authenticated principal may act
// on a scoped surface: the console session is exempt unconditionally, every
// other client must carry the capability scope. A missing InternalClientID
// fails closed before the scoped branch.
func (a Authenticator) applyScopedPolicy(
	principal Principal,
	carriesCapability func(Principal) bool,
	deniedMessage string,
) (Principal, error) {
	if strings.TrimSpace(a.InternalClientID) == "" {
		return Principal{}, backendError()
	}
	// An absent azp identifies a first-party session token; only the built-in
	// client ever mints a token without an azp.
	if principal.ClientID == "" || principal.ClientID == a.InternalClientID {
		return principal, nil
	}
	if !carriesCapability(principal) {
		return Principal{}, authBusinessError(http.StatusForbidden, errcode.CodeForbidden, deniedMessage)
	}
	return principal, nil
}

// RequireDelegatedScope admits a scoped token only when it holds one of the
// allowed scopes. It must be chained after RequireAdminAuth or RequireUserAuth,
// which put the Principal in the context.
//
// The internal console token is exempt (it carries only the three session scopes);
// what this gate bounds is the scoped client whose registered scopes distinguish
// "may read the directory" from "may delete accounts", or "may view my profile"
// from "may change my password".
//
// An empty allowed set rejects every request, like RequireRole: a wiring slip
// must surface as a visible 403, not as an endpoint that quietly accepts any scope.
func (a Authenticator) RequireDelegatedScope(allowed ...string) gin.HandlerFunc {
	permitted := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		permitted[name] = struct{}{}
	}
	return func(c *gin.Context) {
		principal, ok := PrincipalFrom(c)
		if !ok {
			response.Error(c, backendError())
			c.Abort()
			return
		}
		// An unset internal client cannot be compared against, so nothing is
		// exempted from the scope check.
		if strings.TrimSpace(a.InternalClientID) == "" {
			response.Error(c, backendError())
			c.Abort()
			return
		}
		if principal.ClientID == "" || principal.ClientID == a.InternalClientID {
			c.Next()
			return
		}
		for _, name := range principal.Scopes {
			if _, allow := permitted[name]; allow {
				c.Next()
				return
			}
		}
		response.Error(c, authBusinessError(http.StatusForbidden, errcode.CodeForbidden,
			"Access Token 缺少所需 scope"))
		c.Abort()
	}
}

// requireInternalClient pins a principal to the built-in first-party client.
func (a Authenticator) requireInternalClient(principal Principal) error {
	// Fail closed on a missing configuration rather than admitting every client.
	if strings.TrimSpace(a.InternalClientID) == "" {
		return backendError()
	}
	// An absent azp identifies a first-party session token; only the built-in
	// client ever mints a token without an azp.
	if principal.ClientID != "" && principal.ClientID != a.InternalClientID {
		return authBusinessError(http.StatusForbidden, errcode.CodeForbidden,
			"该 Access Token 由第三方客户端签发，不可用于内部接口")
	}
	return nil
}

// SetPrincipal stores an already-validated principal on the request context, so a
// handler that authenticated through Authenticate can expose it to helpers that
// read PrincipalFrom.
func SetPrincipal(c *gin.Context, principal Principal) {
	c.Set(principalContextKey, principal)
}

func PrincipalFrom(c *gin.Context) (Principal, bool) {
	value, ok := c.Get(principalContextKey)
	if !ok {
		return Principal{}, false
	}
	principal, ok := value.(Principal)
	return principal, ok
}

func (a Authenticator) authenticate(ctx context.Context, header string) (Principal, error) {
	token, ok := strictBearerToken(header)
	if !ok {
		return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeUnauthenticated, "未登录（缺少或无效 Authorization Header）")
	}
	if a.JWT == nil || a.Tokens == nil {
		return Principal{}, backendError()
	}
	claims, err := a.JWT.VerifyAccessToken(token)
	if errors.Is(err, auth.ErrExpiredToken) {
		return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenExpired, "Access Token 已过期")
	}
	if err != nil {
		return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenInvalid, "Access Token 无效或已被撤销")
	}
	return a.authenticateClaims(ctx, claims)
}

// authenticateClaims derives the DB-backed principal from an already-verified
// token's claims: it re-checks the token against the authoritative state row
// (auth-state cache with DB fallback), the account state, and the token version.
func (a Authenticator) authenticateClaims(ctx context.Context, claims *auth.TokenClaims) (Principal, error) {
	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil || userID <= 0 || strings.TrimSpace(claims.ID) == "" || claims.ExpiresAt == nil {
		return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenInvalid, "Access Token 无效或已被撤销")
	}
	scopes, err := scope.ParseClaim(claims.Scope)
	if err != nil {
		return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenInvalid, "Access Token 无效或已被撤销")
	}
	// The auth-state cache (Redis, short TTL) lets authenticated requests skip the
	// per-request DB query, falling back to the database on a miss or error.
	// Revocation paths write a short-lived tombstone and the SET NX fill refuses to
	// overwrite it, so a revoked token cannot be admitted by a stale cache.
	state, err := a.authState(ctx, claims.ID)
	if errors.Is(err, repository.ErrNotFound) {
		return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenInvalid, "Access Token 无效或已被撤销")
	}
	if err != nil || state == nil {
		return Principal{}, backendError()
	}
	if state.TokenID != claims.ID || state.UserID != userID || state.RevokedAt != nil || !state.ExpiresAt.After(a.now()) {
		return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenInvalid, "Access Token 无效或已被撤销")
	}
	if state.UserState == model.UserStateDeleted {
		return Principal{}, authBusinessError(http.StatusForbidden, errcode.CodeAccountDeleted, "账号已注销")
	}
	if state.TokenVersion != claims.TokenVersion {
		return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenInvalid, "Access Token 无效或已被撤销")
	}
	return principalFromClaims(claims, userID, scopes, state), nil
}

// principalFromClaims assembles the Principal from verified claims, the parsed
// scopes, and the DB-backed state row. role/state come from the row, never from
// the claims role snapshot, so a demotion lands on the next request.
func principalFromClaims(claims *auth.TokenClaims, userID int64, scopes []string, state *repository.AccessAuthState) Principal {
	role, userState := "", ""
	if state != nil {
		role = string(state.UserRole)
		userState = string(state.UserState)
	}
	return Principal{
		UserID: userID,
		JTI:    claims.ID,
		// The role comes from the database row, not from the claims role snapshot,
		// so a demotion is effective on the next request; claims.Role is still
		// validated for presence but is not what authorization decisions are made
		// on.
		Role:      role,
		State:     userState,
		Scopes:    scopes,
		ClientID:  strings.TrimSpace(claims.AZP),
		ExpiresAt: claims.ExpiresAt.UTC(),
	}
}

// authState resolves the DB-authoritative state for one access token, serving it
// from the short-TTL Redis cache when possible. Fail-open: every cache error
// (get, put, unmarshal) falls back to the database so a cache fault never rejects
// a valid request, and the fault is logged so an outage is visible beyond the
// health check.
//
// The cache must not admit a revoked token. Every revocation path writes a
// short-lived tombstone (never a delete) and cache fills use SET NX, which
// refuses to overwrite a tombstone, so a request whose DB read completed before a
// revoking transaction commits cannot re-seed a pre-revocation blob. A state
// change that does not revoke the token surfaces only after the entry's own TTL;
// nothing authorizes on Principal.State today, so that is currently harmless.
func (a Authenticator) authState(ctx context.Context, jti string) (*repository.AccessAuthState, error) {
	if a.AuthStateCache != nil {
		data, found, err := a.AuthStateCache.GetAuthState(ctx, jti)
		if err != nil {
			slog.WarnContext(ctx, "auth-state cache get failed, using DB", "jti", jti, "error", err)
		} else if found {
			var cached repository.AccessAuthState
			if jsonErr := json.Unmarshal(data, &cached); jsonErr != nil {
				slog.WarnContext(ctx, "auth-state cache entry failed to decode, using DB", "jti", jti, "error", jsonErr)
			} else if cached.TokenID != "" {
				return &cached, nil
			} else {
				slog.WarnContext(ctx, "auth-state cache entry missing token ID, using DB", "jti", jti)
			}
		}
	}
	state, err := a.Tokens.FindAccessAuthStateByJTI(ctx, jti)
	if err != nil {
		return nil, err
	}
	if a.AuthStateCache != nil && a.AuthStateTTL > 0 {
		if data, marshalErr := json.Marshal(state); marshalErr != nil {
			slog.WarnContext(ctx, "auth-state cache marshal failed", "jti", jti, "error", marshalErr)
		} else if putErr := a.AuthStateCache.PutAuthState(ctx, jti, data, a.AuthStateTTL); putErr != nil {
			slog.WarnContext(ctx, "auth-state cache put failed", "jti", jti, "error", putErr)
		}
	}
	return state, nil
}

func strictBearerToken(header string) (string, bool) {
	prefix, token, ok := strings.Cut(header, " ")
	if !ok || prefix != "Bearer" || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func (a Authenticator) now() time.Time {
	if a.Clock != nil {
		return a.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

func authBusinessError(status, code int, message string) error {
	return &response.BusinessError{HTTPStatus: status, Code: code, Message: message}
}

func backendError() error {
	return &response.BusinessError{HTTPStatus: http.StatusInternalServerError, Code: errcode.CodeInternal, Message: "服务器内部错误"}
}
