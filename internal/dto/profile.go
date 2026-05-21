package dto

import "gorm.io/datatypes"

// ==================== 请求 DTO ====================

// ChangeProfileRequest 修改用户资料请求
type ChangeProfileRequest struct {
	Nickname string         `json:"nickname"`
	OrgID    int16          `json:"org_id"`
	Bio      string         `json:"bio"`
	Link     datatypes.JSON `json:"link"`
	Hide     datatypes.JSON `json:"hide"`
}

// ==================== 响应 DTO ====================

// ProfileResponse 用户资料响应 (GET /profile/getProfile)
type ProfileResponse struct {
	ID        int64          `json:"id"`
	Nickname  string         `json:"nickname"`
	OrgID     int16          `json:"org_id"`
	Bio       string         `json:"bio,omitempty"`
	Avatar    string         `json:"avatar,omitempty"`
	Link      datatypes.JSON `json:"link,omitempty"`
	Badge     datatypes.JSON `json:"badge,omitempty"`
	Hide      datatypes.JSON `json:"hide,omitempty"`
	CreatedAt string         `json:"created_at"`
	UpdatedAt string         `json:"updated_at"`
}

// BadgeItem 纪念卡条目结构
type BadgeItem struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Image     string `json:"image"`
	CreatedAt string `json:"created_at"`
}

// LinkItem 社交链接条目结构
type LinkItem struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}
