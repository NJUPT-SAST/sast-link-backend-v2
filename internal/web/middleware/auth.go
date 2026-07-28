package middleware

import (
	"context"
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
	UserID    int64
	JTI       string
	Role      string
	State     string
	Scopes    []string
	ExpiresAt time.Time
}

type JWTVerifier interface {
	VerifyAccessToken(token string) (*auth.TokenClaims, error)
}

type JTIBlacklist interface {
	IsJTIBlacklisted(ctx context.Context, jti string) (bool, error)
}

// AccessAuthStateRepository reads the DB-authoritative access-token state.
type AccessAuthStateRepository interface {
	FindAccessAuthStateByJTI(ctx context.Context, jti string) (*repository.AccessAuthState, error)
}

type Authenticator struct {
	JWT       JWTVerifier
	Blacklist JTIBlacklist
	Tokens    AccessAuthStateRepository
	Clock     auth.Clock
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

// Authenticate validates an Authorization header and returns its principal.
//
// Exported so endpoints that answer in a non-standard error format can reuse the
// exact same validation instead of reimplementing it. OIDC UserInfo is the case:
// RFC 6750 requires a WWW-Authenticate challenge and an {error, error_description}
// body, which this middleware's envelope cannot produce, but the token checks
// themselves — signature, blacklist, DB revocation, token_version, account state —
// must not diverge between the two paths.
//
// The returned error is a *response.BusinessError, so a caller that wants the
// standard envelope can pass it straight to response.Error.
func (a Authenticator) Authenticate(ctx context.Context, header string) (Principal, error) {
	return a.authenticate(ctx, header)
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
	// The Redis blacklist is a fast reject path, not the authority. Every JTI it
	// holds was written in the same transaction that set oauth_access_tokens
	// .revoked_at, so the DB check below rejects a strict superset. Degrade to
	// that check when Redis is unavailable instead of failing the request.
	if a.Blacklist != nil {
		blacklisted, blacklistErr := a.Blacklist.IsJTIBlacklisted(ctx, claims.ID)
		switch {
		case blacklistErr != nil:
			slog.WarnContext(ctx, "jti blacklist unavailable, falling back to database", "error", blacklistErr)
		case blacklisted:
			return Principal{}, authBusinessError(http.StatusUnauthorized, errcode.CodeAccessTokenInvalid, "Access Token 无效或已被撤销")
		}
	}

	state, err := a.Tokens.FindAccessAuthStateByJTI(ctx, claims.ID)
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
		UserID:    userID,
		JTI:       claims.ID,
		Role:      claims.Role,
		State:     string(state.UserState),
		Scopes:    scopes,
		ExpiresAt: claims.ExpiresAt.UTC(),
	}, nil
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
