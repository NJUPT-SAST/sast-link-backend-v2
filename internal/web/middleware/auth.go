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
	// Every access token carries this service as its audience, because the internal
	// API is the resource server for first-party sessions and third-party grants
	// alike. The audience therefore cannot tell them apart, and a third-party token
	// would otherwise be a full session credential: an openid-only grant reaching
	// PUT /user/profile or the email-binding endpoints is account takeover. The azp
	// claim carries the issuing client and this field is what it is pinned to.
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
// Exported so endpoints that answer in a non-standard error format can reuse the
// exact same validation instead of reimplementing it. The token checks — signature,
// auth-state cache, DB revocation, token_version, account state — must not diverge
// between paths.
//
// The returned error is a *response.BusinessError, so a caller that wants the
// standard envelope can pass it straight to response.Error.
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
// design — OIDC UserInfo is the only one — and must never back an internal
// endpoint, where a third-party token acting as a session credential is account
// takeover. Prefer Authenticate.
func (a Authenticator) AuthenticateAnyClient(ctx context.Context, header string) (Principal, error) {
	return a.authenticate(ctx, header)
}

// requireInternalClient pins a principal to the built-in first-party client.
func (a Authenticator) requireInternalClient(principal Principal) error {
	// Fail closed on a missing configuration rather than admitting every client.
	if strings.TrimSpace(a.InternalClientID) == "" {
		return backendError()
	}
	// An absent azp means a first-party session token predating the claim; those are
	// only ever issued to the built-in client.
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
	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil || userID <= 0 || strings.TrimSpace(claims.ID) == "" || claims.ExpiresAt == nil {
		return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenInvalid, "Access Token 无效或已被撤销")
	}
	scopes, err := scope.ParseClaim(claims.Scope)
	if err != nil {
		return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenInvalid, "Access Token 无效或已被撤销")
	}
	// The auth-state cache (Redis, short TTL) lets authenticated requests skip the
	// per-request DB query: on a hit the cached state is the DB-authoritative
	// answer, on a miss the database is read and the cache populated. The
	// revocation paths delete the cache entry, so a revoked token cannot be
	// admitted by a stale cache. Fail-open: a cache error degrades to the
	// database, exactly like the old blacklist fast-reject it replaces.
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
	return Principal{
		UserID: userID,
		JTI:    claims.ID,
		// The role comes from the database row, not from claims.Role. A JWT carries the
		// role as it stood at signing time, so an administrator who has just been
		// demoted would keep administrative access until that token expired. The state
		// query already joins "user" for state and token_version, so reading role from
		// the same row costs no extra round trip and makes a demotion effective on the
		// next request. claims.Role is still validated for presence but is not what
		// authorization decisions are made on.
		Role:      string(state.UserRole),
		State:     string(state.UserState),
		Scopes:    scopes,
		ClientID:  strings.TrimSpace(claims.AZP),
		ExpiresAt: claims.ExpiresAt.UTC(),
	}, nil
}

// authState resolves the DB-authoritative state for one access token, serving it
// from the short-TTL Redis cache when possible. Fail-open: every cache error
// (get, put, unmarshal) falls back to the database so a cache fault never rejects
// a valid request, and the fault is logged so an outage is visible beyond the
// health check.
//
// The cache must not admit a revoked token. Every revocation path writes a
// short-lived tombstone (never a delete) AND enqueues an outbox row the worker
// retries until it lands, so a cache miss falls back to the authoritative DB
// revoked_at check. Cache fills use SET NX, which refuses to overwrite a
// tombstone: a request whose DB read completed before a revoking transaction
// commits cannot re-seed a pre-revocation blob once the tombstone lands. The
// tombstone TTL is sized from the server WriteTimeout so it outlives any
// in-flight request's read-to-PUT gap; "cut access now" operations are effective
// immediately, with the outbox retry covering a failed synchronous write.
//
// A state change that does not revoke the token surfaces only after the cache
// entry's own TTL (AUTH_STATE_CACHE_TTL), which is what that TTL bounds — not the
// post-revocation window, which the tombstone covers regardless of it. Two paths
// land here: an admin edit that moves "user".state without touching role
// (UpdateAdminUser gates revocation on roleChanged), and RestoreUser. Both leave
// live tokens valid, so their cached blob keeps the pre-change state for up to one
// TTL. Nothing authorizes on Principal.State today, so that is currently harmless;
// a future check that gates on state would inherit this window.
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
