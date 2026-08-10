package model

import "time"

// AdminDelegatedClientID is the client_id of the one third-party client permitted
// to call the admin API on an administrator's behalf.
//
// A constant rather than configuration, deliberately: the registration is seeded by
// migration with this exact literal, so an environment variable could only ever
// disagree with the row it is supposed to name — and a mismatch fails silently as
// "delegation refused" rather than loudly. Changing the delegate means a migration,
// which is the same commit that would change this constant.
//
// Its counterpart, the session client seeded alongside it, is deliberately absent
// from this file: it holds openid/profile/email and reads the signed-in user through
// /userinfo, so nothing in this service needs to know its name. Only the client that
// may reach /admin/* has to be named here.
const AdminDelegatedClientID = "sast-people-admin"

// OAuthClient persists a registered OAuth client.
type OAuthClient struct {
	ID               int64
	ClientID         string
	ClientSecretHash *string `gorm:"column:client_secret" json:"-"`
	ClientName       string
	ClientType       ClientType  `gorm:"type:client_enum;not null"`
	RedirectURIs     StringArray `gorm:"type:text[]"`
	GrantTypes       StringArray `gorm:"type:text[]"`
	Scopes           StringArray `gorm:"type:text[];default:(-)"`
	IsActive         *bool       `gorm:"default:(-)"`
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// TableName returns the exact V001 table name for OAuthClient.
func (OAuthClient) TableName() string {
	return "oauth_clients"
}

// OAuthAuthorization persists a single-use OAuth authorization code.
type OAuthAuthorization struct {
	ID                  int64
	Code                string `json:"-"`
	ClientID            int64
	UserID              int64
	RedirectURI         *string     `gorm:"column:redirect_uri"`
	Scopes              StringArray `gorm:"type:text[]"`
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               *string
	IsUsed              bool
	FamilyID            *string `gorm:"column:family_id"`
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

// TableName returns the exact V001 table name for OAuthAuthorization.
func (OAuthAuthorization) TableName() string {
	return "oauth_authorizations"
}

// OAuthAccessToken persists access-token metadata.
type OAuthAccessToken struct {
	ID        int64
	TokenID   string
	ClientID  int64
	UserID    int64
	FamilyID  *string     `gorm:"column:family_id"`
	Scopes    StringArray `gorm:"type:text[]"`
	RevokedAt *time.Time
	ExpiresAt time.Time
	CreatedAt time.Time
}

// TableName returns the exact V001 table name for OAuthAccessToken.
func (OAuthAccessToken) TableName() string {
	return "oauth_access_tokens"
}

// OAuthRefreshToken persists a rotated opaque refresh-token hash.
type OAuthRefreshToken struct {
	ID        int64
	TokenHash string `json:"-"`
	FamilyID  string
	Sequence  int
	ClientID  int64
	UserID    int64
	Scopes    StringArray `gorm:"type:text[]"`
	RevokedAt *time.Time
	ExpiresAt time.Time
	CreatedAt time.Time
}

// TableName returns the exact V001 table name for OAuthRefreshToken.
func (OAuthRefreshToken) TableName() string {
	return "oauth_refresh_tokens"
}

// BlacklistEntry identifies a revoked JWT and the absolute time at which it expires.
// It deliberately contains no token secret.
type BlacklistEntry struct {
	TokenID   string
	ExpiresAt time.Time
}

// TokenBlacklistOutbox persists a revocation delivery until Redis acknowledges it.
type TokenBlacklistOutbox struct {
	ID             int64
	TokenID        string
	ExpiresAt      time.Time
	NextDeliveryAt time.Time
	AttemptCount   int
	LastAttemptAt  *time.Time
	LastError      *string
	ClaimToken     *string
	ClaimedUntil   *time.Time
	CreatedAt      time.Time
}

// TableName returns the exact V004 table name for TokenBlacklistOutbox.
func (TokenBlacklistOutbox) TableName() string {
	return "token_blacklist_outbox"
}
