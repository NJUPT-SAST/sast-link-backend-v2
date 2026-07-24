package middleware

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
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
	Now       func() time.Time
}

func (a Authenticator) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, err := a.authenticate(c.Request.Context(), c.GetHeader("Authorization"))
		if err != nil {
			response.Error(c, err)
			c.Abort()
			return
		}
		c.Set(principalContextKey, principal)
		c.Next()
	}
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
		return Principal{}, authBusinessError(http.StatusUnauthorized, 40100, "未登录（缺少或无效 Authorization Header）")
	}
	if a.JWT == nil || a.Tokens == nil {
		return Principal{}, backendError()
	}
	claims, err := a.JWT.VerifyAccessToken(token)
	if errors.Is(err, auth.ErrExpiredToken) {
		return Principal{}, authBusinessError(http.StatusUnauthorized, 40101, "Access Token 已过期")
	}
	if err != nil {
		return Principal{}, authBusinessError(http.StatusUnauthorized, 40102, "Access Token 无效或已被撤销")
	}
	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil || userID <= 0 || strings.TrimSpace(claims.ID) == "" || claims.ExpiresAt == nil {
		return Principal{}, authBusinessError(http.StatusUnauthorized, 40102, "Access Token 无效或已被撤销")
	}
	scopes, err := scope.ParseClaim(claims.Scope)
	if err != nil {
		return Principal{}, authBusinessError(http.StatusUnauthorized, 40102, "Access Token 无效或已被撤销")
	}
	if a.Blacklist != nil {
		blacklisted, blacklistErr := a.Blacklist.IsJTIBlacklisted(ctx, claims.ID)
		if blacklistErr != nil {
			return Principal{}, backendError()
		}
		if blacklisted {
			return Principal{}, authBusinessError(http.StatusUnauthorized, 40102, "Access Token 无效或已被撤销")
		}
	}

	state, err := a.Tokens.FindAccessAuthStateByJTI(ctx, claims.ID)
	if errors.Is(err, repository.ErrNotFound) {
		return Principal{}, authBusinessError(http.StatusUnauthorized, 40102, "Access Token 无效或已被撤销")
	}
	if err != nil || state == nil {
		return Principal{}, backendError()
	}
	if state.TokenID != claims.ID || state.UserID != userID || state.RevokedAt != nil || !state.ExpiresAt.After(a.now()) {
		return Principal{}, authBusinessError(http.StatusUnauthorized, 40102, "Access Token 无效或已被撤销")
	}
	if state.UserState == model.UserStateDeleted {
		return Principal{}, authBusinessError(http.StatusForbidden, 40301, "账号已注销")
	}
	if state.TokenVersion != claims.TokenVersion {
		return Principal{}, authBusinessError(http.StatusUnauthorized, 40102, "Access Token 无效或已被撤销")
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
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

func authBusinessError(status, code int, message string) error {
	return &response.BusinessError{HTTPStatus: status, Code: code, Message: message}
}

func backendError() error {
	return &response.BusinessError{HTTPStatus: http.StatusInternalServerError, Code: 50000, Message: "服务器内部错误"}
}
