// Package dto defines request and response data transfer objects for API endpoints.
package dto

// ==================== Auth DTOs ====================

// SendCodeRequest 发送验证码请求 (POST /auth/register/send-code, /auth/forgot-password/send-code)
type SendCodeRequest struct {
	LoginEmail string `json:"login_email" binding:"required,email"`
}

// SendCodeResponse 发送验证码响应 (data payload)
type SendCodeResponse struct {
	Message   string `json:"message"`
	ExpiresIn int    `json:"expires_in"`
}

// VerifyRegisterCodeRequest 验证注册验证码请求 (POST /auth/register/verify-code)
type VerifyRegisterCodeRequest struct {
	LoginEmail string `json:"login_email" binding:"required,email"`
	Code       string `json:"code" binding:"required"`
}

// RegisterTicketResponse 验证码校验后返回的 Register-Ticket (data payload)
type RegisterTicketResponse struct {
	RegisterTicket string `json:"register_ticket"`
	ExpiresIn      int    `json:"expires_in"`
}

// RegisterRequest 完成注册请求 (POST /auth/register)
type RegisterRequest struct {
	RegisterTicket string `json:"register_ticket" binding:"required"`
	Password       string `json:"password" binding:"required,min=8"`
	Name           string `json:"name" binding:"required"`
	PhoneNumber    string `json:"phone_number" binding:"required"`
	QQNumber       string `json:"qq_number" binding:"required"`
	StudentID      string `json:"student_id" binding:"required"`
	College        string `json:"college" binding:"required"`
	Major          string `json:"major" binding:"required"`
	OAuthState     string `json:"oauth_state,omitempty"`
}

// LoginRequest 密码登录请求 (POST /user/login)
type LoginRequest struct {
	LoginEmail string `json:"login_email" binding:"required,email"`
	Password   string `json:"password" binding:"required"`
}

// RefreshTokenRequest 刷新 Token 请求 (POST /auth/refresh)
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LogoutRequest 登出请求 (POST /auth/logout)
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// ChangePasswordRequest 修改密码请求 (POST /auth/change-password)
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// ResetPasswordRequest 重置密码请求 (POST /auth/reset-password)
type ResetPasswordRequest struct {
	LoginEmail  string `json:"login_email" binding:"required,email"`
	Code        string `json:"code" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// ExchangeCodeRequest 交换登录码请求 (POST /oauth/exchange-code)
type ExchangeCodeRequest struct {
	Code string `json:"code" binding:"required"`
}

// ==================== 公共响应 payload ====================

// AuthUser 登录/注册成功返回的用户信息
type AuthUser struct {
	ID         int64  `json:"id"`
	LoginEmail string `json:"login_email"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	State      string `json:"state"`
	EmailType  string `json:"email_type"`
	CreatedAt  string `json:"created_at"`
}

// TokenPair 登录/注册成功返回的 Token 信息
type TokenPair struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int      `json:"expires_in"`
	User         AuthUser `json:"user"`
}

// TokenRefreshResponse Token 刷新响应 payload
type TokenRefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}
