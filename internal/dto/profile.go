package dto

import "time"

// ==================== 请求 DTO ====================

// UpdateProfileRequest 更新用户资料请求 (PUT /user/profile)
// 允许更新 user 表基础信息 + profile 表展示资料。
// 未传字段保持不变。
type UpdateProfileRequest struct {
	Name        string `json:"name,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
	QQNumber    string `json:"qq_number,omitempty"`
	College     string `json:"college,omitempty"`
	Major       string `json:"major,omitempty"`
	StudentID   string `json:"student_id,omitempty"`
	Nickname    string `json:"nickname,omitempty"`
	Department  string `json:"department,omitempty"`
	Intro       string `json:"intro,omitempty"`
	Email       string `json:"email,omitempty"`
	BlogURL     string `json:"blog_url,omitempty"`
	GitHubURL   string `json:"github_url,omitempty"`
}

// ==================== 响应 DTO ====================

// ProfileData 用户资料
type ProfileData struct {
	Nickname   string `json:"nickname,omitempty"`
	Department string `json:"department,omitempty"`
	Intro      string `json:"intro,omitempty"`
	Email      string `json:"email,omitempty"`
	Avatar     string `json:"avatar,omitempty"`
	BlogURL    string `json:"blog_url,omitempty"`
	GitHubURL  string `json:"github_url,omitempty"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// IdentityData 第三方绑定记录
// ProviderID 含义按 provider 不同：
//   - github  → GitHub 用户 ID
//   - lark    → 飞书 union_id（非 open_id，union_id 跨应用一致）
//   - other_mail → 绑定邮箱地址
type IdentityData struct {
	ID             int64      `json:"id"`
	Provider       string     `json:"provider"`
	ProviderID     string     `json:"provider_id"`
	IdentityData   any        `json:"identity_data"`
	TokenExpiresAt *time.Time `json:"token_expires_at"`
	CreatedAt      string     `json:"created_at"`
	UpdatedAt      string     `json:"updated_at"`
}

// UserProfileData 完整用户资料
type UserProfileData struct {
	ID          int64          `json:"id"`
	Name        string         `json:"name"`
	LoginEmail  string         `json:"login_email"`
	Role        string         `json:"role"`
	State       string         `json:"state"`
	EmailType   string         `json:"email_type"`
	PhoneNumber string         `json:"phone_number"`
	QQNumber    string         `json:"qq_number"`
	StudentID   string         `json:"student_id"`
	College     string         `json:"college"`
	Major       string         `json:"major"`
	Profile     *ProfileData   `json:"profile"`
	Identities  []IdentityData `json:"identities"`
	CreatedAt   string         `json:"created_at"`
	UpdatedAt   string         `json:"updated_at"`
}

// ProfileUpdateResponse 更新资料响应 payload
type ProfileUpdateResponse struct {
	Message string           `json:"message"`
	User    *UserProfileData `json:"user"`
}

// BindEmailTicketResponse 邮箱绑定 Ticket 响应
type BindEmailTicketResponse struct {
	BindTicket string `json:"bind_ticket"`
	ExpiresIn  int    `json:"expires_in"`
}

// UnbindEmailTicketResponse 邮箱解绑 Ticket 响应
type UnbindEmailTicketResponse struct {
	UnbindEmailTicket string `json:"unbind_email_ticket"`
}

// BindEmailItem 已绑定邮箱条目
type BindEmailItem struct {
	Email      string `json:"email"`
	IsVerified bool   `json:"is_verified"`
	CreatedAt  string `json:"created_at"`
}
