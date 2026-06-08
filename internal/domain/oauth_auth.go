package domain

import "time"

// OAuthAuthorization represents an authorization code issued during OAuth flow.
type OAuthAuthorization struct {
	ID                  int64       `gorm:"column:id;primaryKey;autoIncrement"`
	Code                string      `gorm:"column:code;type:varchar(255);not null;uniqueIndex"`
	ClientID            int64       `gorm:"column:client_id;not null;index:idx_oauth_authorizations_client_id;index:idx_oauth_authorizations_user_client"`
	UserID              int64       `gorm:"column:user_id;not null;index:idx_oauth_authorizations_user_client"`
	RedirectURI         *string     `gorm:"column:redirect_uri;type:varchar(2048)"`
	Scopes              StringArray `gorm:"column:scopes;type:text[]"`
	CodeChallenge       string      `gorm:"column:code_challenge;type:varchar(255);not null"`
	CodeChallengeMethod string      `gorm:"column:code_challenge_method;type:varchar(10);not null"`
	Nonce               *string     `gorm:"column:nonce;type:varchar(255)"`
	IsUsed              bool        `gorm:"column:is_used;not null;default:false"`
	FamilyID            *string     `gorm:"column:family_id;type:varchar(255)"`
	ExpiresAt           time.Time   `gorm:"column:expires_at;type:timestamptz;not null;index:idx_oauth_authorizations_expires_at,where:is_used = false"`
	CreatedAt           time.Time   `gorm:"column:created_at;type:timestamptz;not null;default:now()"`
}

// TableName overrides the default table name.
func (OAuthAuthorization) TableName() string {
	return "oauth_authorizations"
}
