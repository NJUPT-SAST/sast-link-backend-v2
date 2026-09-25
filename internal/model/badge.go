package model

import "time"

// Badge persists a user's opt-in personal badge: the capability-URL key behind
// the public /badge/:key.svg embed. The key is stored verbatim rather than
// hashed: the data it unlocks is exactly the profile the user chose to share
// publicly, so database exposure grants no privilege beyond links the user is
// already handing out.
//
// Toggling sharing never rotates the key: disabled_at marks the state, and a
// saved embed URL recovers the moment the owner switches back on — while off,
// it renders the neutral "closed" card. The key is minted exactly once, on
// the first enable.
type Badge struct {
	ID         int64
	UserID     int64
	BadgeKey   string `gorm:"column:badge_key"`
	EnabledAt  time.Time
	DisabledAt *time.Time `gorm:"column:disabled_at"`
}

// TableName returns the exact V017 table name for Badge.
func (Badge) TableName() string {
	return "badge"
}
