package domain

import "time"

// Profile represents a user's public profile information.
type Profile struct {
	ID         int64      `gorm:"column:id;primaryKey;autoIncrement"`
	UserID     int64      `gorm:"column:user_id;not null;uniqueIndex;index"`
	Nickname   string     `gorm:"column:nickname;type:varchar(255)"`
	Department Department `gorm:"column:department;type:department_enum"`
	Intro      string     `gorm:"column:intro;type:varchar(255)"`
	Email      string     `gorm:"column:email;type:varchar(255)"`
	Avatar     string     `gorm:"column:avatar;type:varchar(512)"`
	BlogURL    string     `gorm:"column:blog_url;type:varchar(512)"`
	GitHubURL  string     `gorm:"column:github_url;type:varchar(512)"`
	CreatedAt  time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt  time.Time  `gorm:"column:updated_at;autoUpdateTime"`
}

func (Profile) TableName() string {
	return "profile"
}
