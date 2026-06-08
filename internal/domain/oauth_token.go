package domain

import "time"

// OAuthAccessToken represents server-side metadata for a JWT access token.
type OAuthAccessToken struct {
	ID        int64       `gorm:"column:id;primaryKey;autoIncrement"`
	TokenID   string      `gorm:"column:token_id;type:varchar(255);not null;uniqueIndex"`
	ClientID  int64       `gorm:"column:client_id;not null;index:idx_oauth_access_tokens_client_id"`
	UserID    int64       `gorm:"column:user_id;not null;index:idx_oauth_access_tokens_user_id"`
	FamilyID  *string     `gorm:"column:family_id;type:varchar(255);index:idx_oauth_access_tokens_family_id"`
	Scopes    StringArray `gorm:"column:scopes;type:text[]"`
	RevokedAt *time.Time  `gorm:"column:revoked_at;type:timestamptz"`
	ExpiresAt time.Time   `gorm:"column:expires_at;type:timestamptz;not null;index:idx_oauth_access_tokens_expires_at"`
	CreatedAt time.Time   `gorm:"column:created_at;type:timestamptz;not null;default:now()"`
}

// TableName overrides the default table name.
func (OAuthAccessToken) TableName() string {
	return "oauth_access_tokens"
}

// OAuthRefreshToken represents an opaque refresh token stored by hash.
type OAuthRefreshToken struct {
	ID        int64       `gorm:"column:id;primaryKey;autoIncrement"`
	TokenHash string      `gorm:"column:token_hash;type:varchar(255);not null;uniqueIndex"`
	FamilyID  string      `gorm:"column:family_id;type:varchar(255);not null;uniqueIndex:uq_oauth_refresh_tokens_family_sequence;index:idx_oauth_refresh_tokens_family_id"`
	Sequence  int         `gorm:"column:sequence;type:int;not null;default:0;uniqueIndex:uq_oauth_refresh_tokens_family_sequence"`
	ClientID  int64       `gorm:"column:client_id;not null;index:idx_oauth_refresh_tokens_client_id"`
	UserID    int64       `gorm:"column:user_id;not null;index:idx_oauth_refresh_tokens_user_id"`
	Scopes    StringArray `gorm:"column:scopes;type:text[]"`
	RevokedAt *time.Time  `gorm:"column:revoked_at;type:timestamptz"`
	ExpiresAt time.Time   `gorm:"column:expires_at;type:timestamptz;not null;index:idx_oauth_refresh_tokens_expires_at,where:revoked_at IS NOT NULL"`
	CreatedAt time.Time   `gorm:"column:created_at;type:timestamptz;not null;default:now()"`
}

// TableName overrides the default table name.
func (OAuthRefreshToken) TableName() string {
	return "oauth_refresh_tokens"
}
