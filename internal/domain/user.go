package domain

import "time"

// User represents a registered user account.
type User struct {
	ID        int64     `gorm:"column:id;primaryKey;autoIncrement"`
	UID       string    `gorm:"column:uid;type:varchar(32);uniqueIndex;not null"`
	Email     string    `gorm:"column:email;type:varchar(128);uniqueIndex;not null"`
	Password  string    `gorm:"column:password;type:varchar(128);not null"`
	QQID      string    `gorm:"column:qq_id;type:varchar(64);default:null"`
	LarkID    string    `gorm:"column:lark_id;type:varchar(64);default:null"`
	GitHubID  string    `gorm:"column:github_id;type:varchar(64);default:null"`
	WeChatID  string    `gorm:"column:wechat_id;type:varchar(64);default:null"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime"`
	IsDeleted bool      `gorm:"column:is_deleted;default:false;not null"`
}

// TableName overrides the default table name.
func (User) TableName() string {
	return "user"
}
