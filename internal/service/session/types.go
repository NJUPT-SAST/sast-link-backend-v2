package session

import (
	"context"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/mailer"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

const BearerTokenType = "Bearer"

// Clock is an alias for auth.Clock to keep the session package's API stable.
type Clock = auth.Clock

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
	// BlacklistJTIBatch delivers a revoked session set in one round trip.
	// Implementations must tolerate an empty map as a no-op.
	BlacklistJTIBatch(ctx context.Context, entries map[string]time.Duration) error
}

type UserRepository interface {
	FindByLoginIdentifier(ctx context.Context, identifier string) (*model.User, error)
	FindByID(ctx context.Context, userID int64) (*model.User, error)
	FindByLoginEmail(ctx context.Context, email string) (*model.User, error)
	ExistsByLoginEmail(ctx context.Context, email string) (bool, error)
	ExistsByStudentID(ctx context.Context, studentID string) (bool, error)
	// ExistsAsEmailAnywhere reports whether the email is used as either a login
	// email or an other_mail identity provider_id, so Register and BindEmail can
	// treat the address as a single global namespace.
	ExistsAsEmailAnywhere(ctx context.Context, email string) (bool, error)
	CreateWithProfile(ctx context.Context, user *model.User, profile *model.Profile) error
	CreateRegistration(ctx context.Context, user *model.User, profile *model.Profile, pairFactory repository.TokenPairFactory) error
	// UpdatePasswordAndRevokeSessions rewrites the password, bumps token_version
	// and revokes every live token of the user atomically, returning the
	// access-token entries still pending blacklist delivery.
	UpdatePasswordAndRevokeSessions(ctx context.Context, userID int64, passwordHash string, revokedAt time.Time) ([]model.BlacklistEntry, error)
	// UpdateProfile applies a partial self-service field update across "user" and
	// profile in one transaction and returns the reloaded aggregate.
	UpdateProfile(ctx context.Context, userID int64, update repository.ProfileUpdate) (*model.User, error)
	// FindPublicCardByUserID returns the public display card of a non-deleted
	// user, or repository.ErrNotFound.
	FindPublicCardByUserID(ctx context.Context, userID int64) (*repository.PublicCard, error)
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

// VerificationCodeStore persists one-time email codes keyed by purpose and
// email, so a code issued for one flow cannot be replayed against another.
type VerificationCodeStore interface {
	SaveVerificationCode(ctx context.Context, purpose, email, code string, ttl time.Duration) error
	// VerifyVerificationCode compares the submitted code against the stored one
	// without discarding it on a wrong guess, so a typo stays recoverable. The
	// store bounds the attempts and drops the code once the budget is spent;
	// remaining reports how many guesses are left after a mismatch.
	VerifyVerificationCode(ctx context.Context, purpose, email, code string) (matched bool, remaining int, err error)
	// DiscardVerificationCode drops an already-matched code so a later failure in
	// the same flow cannot leave it replayable.
	DiscardVerificationCode(ctx context.Context, purpose, email string) error
}

type RegisterTicketStore interface {
	SaveRegisterTicket(ctx context.Context, ticket, email string, ttl time.Duration) error
	// PeekRegisterTicket reads the verified email without consuming the ticket, so
	// a rejectable request does not spend it.
	PeekRegisterTicket(ctx context.Context, ticket string) (email string, found bool, err error)
	// ConsumeRegisterTicket deletes the ticket once the account exists. Races
	// between concurrent registrations are settled by the login_email unique
	// constraint, not by this delete, so the caller does not need to know whether
	// it was the one that removed the key.
	ConsumeRegisterTicket(ctx context.Context, ticket string) error
}

type BindTicketPayload struct {
	Email  string
	UserID int64
}

type BindTicketStore interface {
	SaveBindTicket(ctx context.Context, ticket string, payload BindTicketPayload, ttl time.Duration) error
	// PeekBindTicket reads a ticket without consuming it, so a wrong verification
	// code does not cost the user their ticket.
	PeekBindTicket(ctx context.Context, ticket string) (payload BindTicketPayload, found bool, err error)
	// ConsumeBindTicket atomically deletes the ticket, reporting whether this
	// caller was the one that removed it. Callers rely on that to serialize
	// concurrent binds using the same ticket.
	ConsumeBindTicket(ctx context.Context, ticket string) (consumed bool, err error)
}

type IdentityRepository interface {
	CountByUserAndProvider(ctx context.Context, userID int64, provider model.LoginMethod) (int64, error)
	FindByProviderID(ctx context.Context, provider model.LoginMethod, providerID string) (*model.Identity, error)
	// CreateWithinLimit inserts the identity only while the user owns fewer than
	// limit identities of the same provider, checked under a row lock so
	// concurrent binds cannot exceed the limit.
	CreateWithinLimit(ctx context.Context, identity *model.Identity, limit int64) error
}

type Mailer interface {
	SendVerificationCode(ctx context.Context, to, code string, purpose mailer.VerificationPurpose) error
}

type ForgotPasswordJob struct {
	Email     string
	ClientIP  string
	UserAgent string
}

type ForgotPasswordDispatcher interface {
	EnqueueForgotPassword(job ForgotPasswordJob) bool
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
	ClientIP     string
	UserAgent    string
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
	PrincipalJTI    string
	PrincipalUserID int64
	RefreshToken    string
	ClientIP        string
	UserAgent       string
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

type SendRegisterCodeInput struct {
	Email     string
	ClientIP  string
	UserAgent string
}

type SendRegisterCodeResult struct {
	Email     string
	ExpiresIn int
}

type VerifyRegisterCodeInput struct {
	Email     string
	Code      string
	ClientIP  string
	UserAgent string
}

type VerifyRegisterCodeResult struct {
	RegisterTicket string
	Email          string
	ExpiresIn      int
}

type RegisterInput struct {
	RegisterTicket string
	Password       string
	Name           string
	StudentID      string
	PhoneNumber    string
	QQNumber       string
	College        string
	Major          string
	// RegistrationState and OAuthState are the optional third-party OAuth
	// no-binding registration pair. They are accepted at the contract level but
	// rejected until the OAuth login flows are implemented.
	RegistrationState string
	OAuthState        string
	ClientIP          string
	UserAgent         string
}

type RegisterResult struct {
	AccessToken      string
	RefreshToken     string
	TokenType        string
	Scope            string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	Profile          UserProfileDTO
}

type ForgotPasswordInput struct {
	Email     string
	ClientIP  string
	UserAgent string
}

type ForgotPasswordResult struct {
	Email     string
	ExpiresIn int
}

type ResetPasswordInput struct {
	Email     string
	Code      string
	Password  string
	ClientIP  string
	UserAgent string
}

type ResetPasswordResult struct {
	Email string
}

type ChangePasswordInput struct {
	UserID      int64
	OldPassword string
	NewPassword string
	ClientIP    string
	UserAgent   string
}

type ChangePasswordResult struct {
	UserID int64
}

type BindEmailSendCodeInput struct {
	UserID    int64
	Email     string
	ClientIP  string
	UserAgent string
}

type BindEmailSendCodeResult struct {
	BindTicket string
	ExpiresIn  int
}

type BindEmailVerifyInput struct {
	UserID     int64
	BindTicket string
	Code       string
	ClientIP   string
	UserAgent  string
}

type BindEmailVerifyResult struct {
	Email    string
	Identity IdentityDTO
}

// UpdateProfileInput carries a partial self-service profile edit. Every field is
// a pointer so "absent" is distinguishable from "set to empty": PUT
// /user/profile leaves unsent fields untouched, while an explicit empty string
// clears a nullable display field.
type UpdateProfileInput struct {
	UserID int64

	Name        *string
	PhoneNumber *string
	QQNumber    *string
	StudentID   *string
	College     *string
	Major       *string

	Nickname   *string
	Department *string
	Intro      *string
	Email      *string
	BlogURL    *string
	GitHubURL  *string

	ClientIP  string
	UserAgent string
}

type CardInput struct {
	UserID int64
}

type CardResult struct {
	Card CardDTO
}

// CardDTO is the public display card. Only PRD §4.14's public fields appear
// here; nothing from the user's identity or permission columns is carried.
type CardDTO struct {
	ID         int64
	Nickname   *string
	Department *string
	Intro      *string
	Avatar     *string
	BlogURL    *string
	GitHubURL  *string
}

type UpdateProfileResult struct {
	Profile UserProfileDTO
	// ChangedFields lists the request fields that were applied, in contract
	// order. It feeds the update_profile audit detail defined in PRD §4.13.
	ChangedFields []string
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
