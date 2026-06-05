package dto

// ==================== 请求 DTO ====================

// OAuthRegisterRequest OAuth 注册补全请求（废弃 — 由 /auth/register 的 oauth_state 参数替代）
//
// Deprecated: use RegisterRequest.OAuthState instead.
type OAuthRegisterRequest struct {
	OAuthTicket string `json:"oauth_ticket" binding:"required"`
	Email       string `json:"email" binding:"required,email"`
	Captcha     string `json:"captcha" binding:"required"`
	Password    string `json:"password" binding:"required,min=8"`
}

// OAuthBindExistingRequest OAuth 绑定已有账号请求
type OAuthBindExistingRequest struct {
	OAuthTicket string `json:"oauth_ticket" binding:"required"`
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required"`
}

// ==================== 响应 DTO ====================

// TokenPairResponse Access + Refresh Token 响应
type TokenPairResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

// UserInfoResponse 用户信息响应
type UserInfoResponse struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

// BindStatusResponse OAuth 绑定状态响应
type BindStatusResponse struct {
	GitHub bool `json:"github"`
	Lark   bool `json:"lark"`
}

// UploadAvatarResponse 上传头像响应
type UploadAvatarResponse struct {
	AvatarURL string `json:"avatar_url"`
}
