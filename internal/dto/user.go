package dto

// ==================== 请求 DTO ====================

// RegisterRequest 用户注册请求 (POST /user/register)
// 需已通过 verify/captcha，仅设置密码
type RegisterRequest struct {
	Password string `json:"password" binding:"required"`
}

// LoginRequest 用户登录请求 (POST /user/login)
type LoginRequest struct {
	Password string `json:"password" binding:"required"`
}

// ChangePasswordRequest 修改密码请求 (POST /user/changePassword)
type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword" binding:"required"`
	NewPassword string `json:"newPassword" binding:"required"`
}

// ResetPasswordRequest 重置密码请求 (POST /user/resetPassword)
// 需已通过 verify/captcha，仅设置新密码
type ResetPasswordRequest struct {
	Password string `json:"password" binding:"required"`
}

// OAuthRegisterRequest OAuth 注册补全请求 (POST /user/oauthRegister)
type OAuthRegisterRequest struct {
	OAuthTicket string `json:"oauthTicket" binding:"required"`
	Email       string `json:"email" binding:"required"`
	Captcha     string `json:"captcha" binding:"required"`
	Password    string `json:"password" binding:"required"`
}

// OAuthBindExistingRequest OAuth 绑定已有账号 (POST /user/oauthBindExisting)
type OAuthBindExistingRequest struct {
	OAuthTicket string `json:"oauthTicket" binding:"required"`
	Email       string `json:"email" binding:"required"`
	Password    string `json:"password" binding:"required"`
}

// ==================== 响应 DTO ====================

// TokenPairResponse Access + Refresh Token 响应
type TokenPairResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int    `json:"expiresIn,omitempty"`
}

// UserInfoResponse 用户信息响应 (GET /user/info)
type UserInfoResponse struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
}

// BindStatusResponse OAuth 绑定状态响应 (GET /profile/bindStatus)
type BindStatusResponse struct {
	GitHub bool `json:"github"`
	Lark   bool `json:"lark"`
}

// UploadAvatarResponse 上传头像响应 (POST /profile/uploadAvatar)
type UploadAvatarResponse struct {
	FilePath string `json:"filePath"`
}
