package domain

import "gorm.io/datatypes"

type Profile struct {
	ID        int64          `gorm:"column:id;primaryKey;autoIncrement"`
	UserID    int64          `gorm:"column:user_id;not null;index"`
	Nickname  string         `gorm:"column:nickname;type:varchar(64);not null"`
	Email     string         `gorm:"column:email;type:varchar(128);not null"`
	Avatar    string         `gorm:"column:avatar;type:varchar(256);not null;default:''"`
	OrgID     int16          `gorm:"column:org_id;type:smallint;default:-1"`
	Bio       string         `gorm:"column:bio;type:text;default:null"`
	Link      []string       `gorm:"column:link;type:varchar(256)[];default:null"`
	Badge     datatypes.JSON `gorm:"column:badge;type:jsonb;default:null"`
	Hide      []string       `gorm:"column:hide;type:varchar(30)[];default:null"`
	IsDeleted bool           `gorm:"column:is_deleted;default:false;not null"`
}

// TableName overrides the default table name.
func (Profile) TableName() string {
	return "profile"
}
