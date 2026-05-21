package dto

// ==================== 请求 DTO ====================

// RegisterRequest 用户注册请求
type RegisterRequest struct {
	Password string `form:"password" json:"password" binding:"required"`
}

// LoginRequest 用户登录请求
type LoginRequest struct {
	Password string `form:"password" json:"password" binding:"required"`
}

// ChangePasswordRequest 修改密码请求
type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword" binding:"required"`
	NewPassword string `json:"newPassword" binding:"required"`
}

// ResetPasswordRequest 重置密码请求
type ResetPasswordRequest struct {
	NewPassword string `form:"newPassword" json:"newPassword" binding:"required"`
}

// ==================== 响应 DTO ====================

// UserInfoResponse 用户信息响应 (GET /user/info)
type UserInfoResponse struct {
	Email  string `json:"email"`
	UserID int64  `json:"userId"`
}

// LoginTokenResponse 登录 Token 响应
type LoginTokenResponse struct {
	LoginToken string `json:"loginToken"`
}

// BindStatusResponse OAuth 绑定状态响应
type BindStatusResponse []string

// UploadAvatarResponse 上传头像响应
type UploadAvatarResponse struct {
	FilePath string `json:"filePath"`
}
