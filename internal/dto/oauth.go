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

// OAuthLoginResponse OAuth 登录响应
// 已绑定返回 loginToken，未绑定返回 oauthTicket
type OAuthLoginResponse struct {
	LoginToken  string `json:"loginToken,omitempty"`
	OauthTicket string `json:"oauthTicket,omitempty"`
}

// OAuthBindRequest OAuth 绑定请求（登录时附带 OAUTH-TICKET）
type OAuthBindRequest struct {
	OauthTicket string `header:"OAUTH-TICKET"`
}
