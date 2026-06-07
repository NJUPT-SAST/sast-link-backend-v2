package domain

import "time"

// OAuthClient represents an OAuth client application.
type OAuthClient struct {
	ID           int64       `gorm:"column:id;primaryKey;autoIncrement"`
	ClientID     string      `gorm:"column:client_id;type:varchar(255);not null;uniqueIndex"`
	ClientSecret *string     `gorm:"column:client_secret;type:varchar(255)"`
	ClientName   string      `gorm:"column:client_name;type:varchar(255);not null"`
	ClientType   ClientType  `gorm:"column:client_type;type:client_enum;not null"`
	RedirectURIs StringArray `gorm:"column:redirect_uris;type:text[];not null"`
	GrantTypes   StringArray `gorm:"column:grant_types;type:text[];not null"`
	Scopes       StringArray `gorm:"column:scopes;type:text[];not null;default:'{}'"`
	IsActive     bool        `gorm:"column:is_active;not null;default:true"`
	CreatedAt    time.Time   `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt    time.Time   `gorm:"column:updated_at;autoUpdateTime"`
}

// TableName overrides the default table name.
func (OAuthClient) TableName() string {
	return "oauth_clients"
}
