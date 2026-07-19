package model

import "time"

// User persists an identity account.
type User struct {
	ID           int64
	Role         UserRole `gorm:"type:user_role_enum;not null;default:(-)"`
	Name         string
	PhoneNumber  string
	QQNumber     string
	PasswordHash string    `gorm:"column:password;not null" json:"-"`
	StudentID    string    `gorm:"not null"`
	State        UserState `gorm:"type:state_enum;not null;default:(-)"`
	EmailType    EmailType `gorm:"type:email_enum;not null;default:(-)"`
	LoginEmail   string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	College      College `gorm:"type:college_enum;not null;default:(-)"`
	Major        string
	TokenVersion int
	Profile      *Profile   `gorm:"foreignKey:UserID"`
	Identities   []Identity `gorm:"foreignKey:UserID"`
}

// TableName returns the exact V001 table name for User.
func (User) TableName() string {
	return "user"
}

// Profile persists the optional display-card data for a User.
type Profile struct {
	ID         int64
	UserID     int64
	Nickname   *string
	Department *Department `gorm:"type:department_enum"`
	Intro      *string
	Email      *string
	Avatar     *string
	BlogURL    *string `gorm:"column:blog_url"`
	GitHubURL  *string `gorm:"column:github_url"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// TableName returns the exact V001 table name for Profile.
func (Profile) TableName() string {
	return "profile"
}

// Identity persists a third-party login binding.
type Identity struct {
	ID             int64
	UserID         int64
	Provider       LoginMethod `gorm:"type:login_method_enum;not null"`
	ProviderID     string
	IdentityData   JSONB   `gorm:"type:jsonb"`
	AccessToken    *string `json:"-"`
	RefreshToken   *string `json:"-"`
	TokenExpiresAt *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// TableName returns the exact V001 table name for Identity.
func (Identity) TableName() string {
	return "identities"
}
