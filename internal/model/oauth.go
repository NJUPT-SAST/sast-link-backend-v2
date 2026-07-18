package model

import "time"

// OAuthClient persists a registered OAuth client. It is not an API DTO.
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

// OAuthAuthorization persists a single-use OAuth authorization code. It is not an API DTO.
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

// OAuthAccessToken persists access-token metadata. It is not an API DTO.
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

// OAuthRefreshToken persists a rotated opaque refresh-token hash. It is not an API DTO.
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
