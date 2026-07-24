package session

import (
	"context"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

const BearerTokenType = "Bearer"

type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type LimitResult struct {
	Allowed    bool
	RetryAfter time.Duration
}

type EndpointLimiter interface {
	Allow(ctx context.Context, endpoint, subject string) (LimitResult, error)
}

type LoginFailureResult struct {
	Count  int
	TTL    time.Duration
	Locked bool
}

type LoginFailureStore interface {
	IsLocked(ctx context.Context, key string) (bool, time.Duration, error)
	RecordFailure(ctx context.Context, key string) (LoginFailureResult, error)
	Reset(ctx context.Context, key string) error
}

type TokenBlacklist interface {
	BlacklistJTI(ctx context.Context, jti string, ttl time.Duration) error
}

type UserRepository interface {
	FindByLoginIdentifier(ctx context.Context, identifier string) (*model.User, error)
	FindByID(ctx context.Context, userID int64) (*model.User, error)
}

type ClientRepository interface {
	FindActiveByClientID(ctx context.Context, clientID string) (*model.OAuthClient, error)
}

type TokenRepository interface {
	CreatePair(ctx context.Context, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) error
	RotateRefreshToken(ctx context.Context, currentRefreshTokenHash string, access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) error
	FindRefreshToken(ctx context.Context, tokenHash string) (*model.OAuthRefreshToken, error)
	FindAccessTokenByJTI(ctx context.Context, jti string) (*model.OAuthAccessToken, error)
	RevokeFamily(ctx context.Context, familyID string, revokedAt time.Time) ([]model.BlacklistEntry, error)
}

type AuditRepository interface {
	Create(ctx context.Context, entry *model.AuditLog) error
}

type LoginInput struct {
	Identifier string
	Password   string
	ClientIP   string
	UserAgent  string
}

type LoginResult struct {
	AccessToken      string
	RefreshToken     string
	TokenType        string
	Scope            string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	Profile          UserProfileDTO
}

type RefreshInput struct {
	RefreshToken string
}

type RefreshResult struct {
	AccessToken      string
	RefreshToken     string
	TokenType        string
	Scope            string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

type LogoutInput struct {
	PrincipalJTI       string
	PrincipalUserID    int64
	PrincipalExpiresAt time.Time
	RefreshToken       string
	ClientIP           string
	UserAgent          string
}

type LogoutResult struct {
	BlacklistedJTI string
	FamilyID       string
}

type ProfileInput struct {
	UserID int64
}

type ProfileResult struct {
	Profile UserProfileDTO
}

type UserProfileDTO struct {
	ID          int64
	Name        string
	LoginEmail  string
	Role        string
	State       string
	EmailType   string
	PhoneNumber string
	QQNumber    string
	StudentID   string
	College     string
	Major       string
	Profile     *ProfileDetailDTO
	Identities  []IdentityDTO
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ProfileDetailDTO struct {
	Nickname   *string
	Department *string
	Intro      *string
	Email      *string
	Avatar     *string
	BlogURL    *string
	GitHubURL  *string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type IdentityDTO struct {
	ID             int64
	Provider       string
	ProviderID     string
	IdentityData   model.JSONB
	TokenExpiresAt *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
