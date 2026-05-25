package dto

import "gorm.io/datatypes"

// ==================== 请求 DTO ====================

// ChangeProfileRequest 修改用户资料请求 (POST /profile/changeProfile)
type ChangeProfileRequest struct {
	Nickname string         `json:"nickname"`
	OrgID    int16          `json:"orgId"`
	Bio      string         `json:"bio"`
	Link     []LinkItem     `json:"link"`
	Hide     datatypes.JSON `json:"hide"`
}

// BindEmailRequest 发起邮箱绑定 (POST /profile/bindEmail)
type BindEmailRequest struct {
	Email string `json:"email" binding:"required"`
}

// VerifyBindEmailRequest 验证并完成邮箱绑定 (POST /profile/verifyBindEmail)
type VerifyBindEmailRequest struct {
	Email   string `json:"email" binding:"required"`
	Captcha string `json:"captcha" binding:"required"`
}

// UnbindEmailRequest 发起邮箱解绑 (POST /profile/unbindEmail)
type UnbindEmailRequest struct {
	Email string `json:"email" binding:"required"`
}

// ConfirmUnbindEmailRequest 确认解绑邮箱 (POST /profile/confirmUnbindEmail)
type ConfirmUnbindEmailRequest struct {
	Email   string `json:"email" binding:"required"`
	Captcha string `json:"captcha" binding:"required"`
}

// UnbindOAuthRequest 解除第三方 OAuth 绑定 (POST /profile/unbind)
type UnbindOAuthRequest struct {
	Provider string `json:"provider" binding:"required,oneof=github lark"`
}

// ==================== 响应 DTO ====================

// ProfileResponse 用户资料响应 (GET /profile/getProfile)
type ProfileResponse struct {
	UserID   string         `json:"userId"`
	Nickname string         `json:"nickname"`
	Email    string         `json:"email"`
	Avatar   string         `json:"avatar,omitempty"`
	Org      *ProfileOrg    `json:"org,omitempty"`
	Bio      string         `json:"bio,omitempty"`
	Link     []LinkItem     `json:"link,omitempty"`
	Badge    datatypes.JSON `json:"badge,omitempty"`
	Hide     datatypes.JSON `json:"hide,omitempty"`
}

// ProfileOrg 组织信息
type ProfileOrg struct {
	Dep string `json:"dep"`
	Org string `json:"org"`
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

// BindEmailTicketResponse 邮箱绑定 Ticket 响应
type BindEmailTicketResponse struct {
	BindEmailTicket string `json:"bindEmailTicket"`
}

// UnbindEmailTicketResponse 邮箱解绑 Ticket 响应
type UnbindEmailTicketResponse struct {
	UnbindEmailTicket string `json:"unbindEmailTicket"`
}

// BindEmailItem 已绑定邮箱条目 (GET /profile/emails)
type BindEmailItem struct {
	Email      string `json:"email"`
	IsVerified bool   `json:"isVerified"`
	CreatedAt  string `json:"createdAt"`
}
