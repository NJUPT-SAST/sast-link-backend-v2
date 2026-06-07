package domain

import (
	"time"

	"gorm.io/datatypes"
)

// Identity represents a third-party account bound to a user.
type Identity struct {
	ID             int64          `gorm:"column:id;primaryKey;autoIncrement"`
	UserID         int64          `gorm:"column:user_id;not null;index:idx_identities_user_id;uniqueIndex:uq_identities_user_github,where:provider = 'github';uniqueIndex:uq_identities_user_lark,where:provider = 'lark'"`
	Provider       LoginMethod    `gorm:"column:provider;type:login_method_enum;not null;index:idx_identities_provider;uniqueIndex:uq_identities_provider_provider_id;uniqueIndex:uq_identities_user_github,where:provider = 'github';uniqueIndex:uq_identities_user_lark,where:provider = 'lark'"`
	ProviderID     string         `gorm:"column:provider_id;type:varchar(255);not null;uniqueIndex:uq_identities_provider_provider_id"`
	IdentityData   datatypes.JSON `gorm:"column:identity_data;type:jsonb"`
	AccessToken    *string        `gorm:"column:access_token;type:text"`
	RefreshToken   *string        `gorm:"column:refresh_token;type:text"`
	TokenExpiresAt *time.Time     `gorm:"column:token_expires_at;type:timestamptz"`
	CreatedAt      time.Time      `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt      time.Time      `gorm:"column:updated_at;autoUpdateTime"`
}

// TableName overrides the default table name.
func (Identity) TableName() string {
	return "identities"
}
