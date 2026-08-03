package session

import (
	"context"
	"io"
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
	// CreateRegistrationWithIdentity additionally persists a third-party binding
	// in the same transaction, for registration completed through OAuth.
	CreateRegistrationWithIdentity(ctx context.Context, user *model.User, profile *model.Profile, identity *model.Identity, pairFactory repository.TokenPairFactory) error
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

// OAuthRegistrationPayload is the third-party identity parked by the OAuth
// callback for a user who has no account yet.
//
// This mirrors oauthlogin.RegistrationPayload rather than importing it: the
// OAuth login service already depends on repository and model, and having it
// import session (or session import it) would couple the two flows in a cycle.
// The Redis adapter is what keeps the two shapes reading the same key.
type OAuthRegistrationPayload struct {
	Provider       model.LoginMethod `json:"provider"`
	ProviderID     string            `json:"provider_id"`
	IdentityData   model.JSONB       `json:"identity_data"`
	OAuthState     string            `json:"oauth_state"`
	AccessToken    string            `json:"access_token,omitempty"`
	RefreshToken   string            `json:"refresh_token,omitempty"`
	TokenExpiresAt *time.Time        `json:"token_expires_at,omitempty"`
}

// OAuthRegistrationStore reads the identity parked by an OAuth callback.
//
// Fail-closed: Redis holds the only copy, so an unreadable value must reject the
// registration rather than fall back to creating an unbound account — the user
// asked to register through a provider and would otherwise get an account with
// no binding and no way to tell.
type OAuthRegistrationStore interface {
	// ConsumeRegistrationState atomically reads and deletes the parked identity.
	ConsumeRegistrationState(ctx context.Context, state string) (payload OAuthRegistrationPayload, found bool, err error)
}

type IdentityRepository interface {
	CountByUserAndProvider(ctx context.Context, userID int64, provider model.LoginMethod) (int64, error)
	FindByProviderID(ctx context.Context, provider model.LoginMethod, providerID string) (*model.Identity, error)
	// CreateWithinLimit inserts the identity only while the user owns fewer than
	// limit identities of the same provider, checked under a row lock so
	// concurrent binds cannot exceed the limit.
	CreateWithinLimit(ctx context.Context, identity *model.Identity, limit int64) error
	// ListByUser returns every identity owned by the user, oldest first.
	ListByUser(ctx context.Context, userID int64) ([]model.Identity, error)
	// FindByIDAndUser resolves an identity scoped to its owner, so a foreign ID is
	// indistinguishable from a missing one.
	FindByIDAndUser(ctx context.Context, identityID, userID int64) (*model.Identity, error)
	// DeleteByIDAndUser removes an owned identity, reporting
	// repository.ErrNotFound when nothing matched.
	DeleteByIDAndUser(ctx context.Context, identityID, userID int64) error
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
	// RegistrationState and OAuthState are the third-party OAuth registration
	// pair. Both must be present together or both absent: PRD §4.5 binds the
	// parked identity to the OAuth state it was issued with, so one without the
	// other is rejected rather than silently ignored.
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

type ListIdentitiesInput struct {
	UserID int64
}

type ListIdentitiesResult struct {
	Identities []IdentityDTO
}

type UnbindIdentityInput struct {
	UserID     int64
	IdentityID int64
	Password   string
	ClientIP   string
	UserAgent  string
}

type UnbindIdentityResult struct {
	Provider   string
	ProviderID string
}

type CardInput struct {
	UserID int64
	// ClientIP is the rate-limit subject. This endpoint is unauthenticated, so
	// the caller IP is the only key available.
	ClientIP string
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

// UploadAvatarInput is the PUT /user/avatar request. The file content is passed
// as a reader so the handler owns multipart parsing while the service owns every
// size and format rule. Filename is only used for diagnostics.
//
// Size is the declared content length from the multipart part header. The
// service still reads through a LimitReader: the declared size is trusted for
// nothing beyond an early rejection, because the actual stream is what gets
// stored.
type UploadAvatarInput struct {
	UserID    int64
	Filename  string
	Content   io.Reader
	Size      int64
	ClientIP  string
	UserAgent string
}

type UploadAvatarResult struct {
	// AvatarURL is the public URL now stored in profile.avatar.
	AvatarURL string
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
