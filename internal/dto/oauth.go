package dto

// ==================== 请求 DTO ====================

// OAuthCallbackRequest OAuth 回调请求参数
type OAuthCallbackRequest struct {
	Code  string `form:"code" binding:"required"`
	State string `form:"state" binding:"required"`
}

// OAuthLoginRequest OAuth 登录入口请求
type OAuthLoginRequest struct {
	RedirectURL string `form:"redirect_url"`
}

// ==================== 响应 DTO ====================

// OAuthTempUserInfo OAuth 未绑定时的临时用户信息
type OAuthTempUserInfo struct {
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
}

// OAuthPendingResponse OAuth 回调未绑定响应
type OAuthPendingResponse struct {
	OAuthTicket string            `json:"oauthTicket"`
	Profile     OAuthTempUserInfo `json:"profile"`
}

// OAuthCallbackResponse OAuth 登录回调响应（已绑定返回 Token，未绑定返回 Pending）
type OAuthCallbackResponse struct {
	AccessToken  string             `json:"accessToken,omitempty"`
	RefreshToken string             `json:"refreshToken,omitempty"`
	ExpiresIn    int                `json:"expiresIn,omitempty"`
	OAuthTicket  string             `json:"oauthTicket,omitempty"`
	Profile      *OAuthTempUserInfo `json:"profile,omitempty"`
}
