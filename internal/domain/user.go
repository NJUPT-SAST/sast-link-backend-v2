package domain

import "time"

// User represents a registered user account.
type User struct {
	ID         int64     `gorm:"column:id;primaryKey;autoIncrement"`
	Role       UserRole  `gorm:"column:role;type:user_role_enum;not null;default:freshman"`
	Name       string    `gorm:"column:name;type:varchar(255);not null"`
	Phone      string    `gorm:"column:phone_number;type:varchar(20);not null"`
	QQNumber   string    `gorm:"column:qq_number;type:varchar(20);not null"`
	Password   string    `gorm:"column:password;type:varchar(512);not null"`
	StudentID  string    `gorm:"column:student_id;type:varchar(50);uniqueIndex"`
	State      UserState `gorm:"column:state;type:state_enum;not null;default:njupter"`
	EmailType  EmailType `gorm:"column:email_type;type:email_enum;not null"`
	LoginEmail string    `gorm:"column:login_email;type:varchar(255);uniqueIndex;not null"`
	CreatedAt  time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt  time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

// TableName overrides the default table name.
func (User) TableName() string {
	return "user"
}
