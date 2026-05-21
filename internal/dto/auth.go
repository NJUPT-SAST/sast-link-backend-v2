// Package dto defines request and response data transfer objects for API endpoints.
package dto

// ==================== 请求 DTO ====================

// VerifyAccountRequest 验证账号请求 (POST /verify/account)
// 实际通过 Query 参数传递：username, flag
type VerifyAccountRequest struct {
	Username string `form:"username" binding:"required"`
	Flag     int    `form:"flag" binding:"min=0,max=2"` // 0=注册, 1=登录, 2=重置密码
}

// VerifyCaptchaRequest 验证验证码请求 (POST /verify/captcha)
type VerifyCaptchaRequest struct {
	Captcha string `form:"captcha" binding:"required"`
}

// ==================== 响应 DTO ====================

// TicketResponse Ticket 响应（registerTicket / loginTicket / resetPwdTicket）
type TicketResponse struct {
	Ticket string `json:"ticket"`
}

// RegisterTicketResponse 注册 Ticket 响应
type RegisterTicketResponse struct {
	RegisterTicket string `json:"registerTicket"`
}

// LoginTicketResponse 登录 Ticket 响应
type LoginTicketResponse struct {
	LoginTicket string `json:"loginTicket"`
}

// ResetPwdTicketResponse 重置密码 Ticket 响应
type ResetPwdTicketResponse struct {
	ResetPwdTicket string `json:"resetPwdTicket"`
}
