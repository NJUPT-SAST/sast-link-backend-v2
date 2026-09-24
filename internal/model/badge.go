package model

import "time"

// Badge persists a user's opt-in personal badge: the capability-URL key behind
// the public /badge/:key.svg embed. Row existence is the enable flag —
// deleting the row disables the badge, and a fresh enable mints a new key so a
// retired link never resurrects. The key is stored verbatim rather than
// hashed: the data it unlocks is exactly the profile the user chose to share
// publicly, so database exposure grants no privilege beyond links the user is
// already handing out.
type Badge struct {
	ID        int64
	UserID    int64
	BadgeKey  string `gorm:"column:badge_key"`
	EnabledAt time.Time
}

// TableName returns the exact V017 table name for Badge.
func (Badge) TableName() string {
	return "badge"
}
