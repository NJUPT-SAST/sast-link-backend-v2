package dto

// ==================== 请求 DTO ====================

// OAuthCallbackRequest OAuth 回调请求参数 (GET /oauth/{provider}/callback)
type OAuthCallbackRequest struct {
	Code  string `form:"code" binding:"required"`
	State string `form:"state" binding:"required"`
}

// ==================== 响应 DTO ====================

// OAuthTempUserInfo OAuth 未绑定时的临时用户信息
type OAuthTempUserInfo struct {
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
}

// OAuthPendingData OAuth 回调未绑定时的 data payload
type OAuthPendingData struct {
	OAuthState string `json:"oauth_state"`
	Provider   string `json:"provider"`
	Name       string `json:"name"`
	Avatar     string `json:"avatar,omitempty"`
}
