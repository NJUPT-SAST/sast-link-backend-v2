// Package dto defines request and response data transfer objects for API endpoints.
package dto

// ==================== 请求 DTO ====================

// VerifyAccountRequest 验证账号请求 (POST /verify/account)
// 通过 Query 参数传递：username, flag
type VerifyAccountRequest struct {
	Username string `form:"username" binding:"required"`
	Flag     int    `form:"flag" binding:"min=0,max=2"` // 0=注册, 1=登录, 2=重置密码
}

// VerifyCaptchaRequest 验证验证码请求 (POST /verify/captcha)
type VerifyCaptchaRequest struct {
	Captcha string `json:"captcha" form:"captcha" binding:"required"`
}

// SendEmailRequest 发送验证邮件请求 (POST /sendEmail)
type SendEmailRequest struct {
	Email string `json:"email" form:"email" binding:"required"`
}

// ==================== 响应 DTO ====================

// VerifyAccountResponse 账号验证 Ticket 响应
type VerifyAccountResponse struct {
	Ticket     string `json:"ticket"`
	TicketType string `json:"ticketType"` // register | login | resetPwd
}
