// Package errcode holds the canonical API business error codes documented in
// docs/API文档.md.
package errcode

const (
	// CodeBadRequest covers every malformed-request outcome, including a missing
	// field and a type mismatch. 40001 (缺少必要参数) and 40002 (参数格式错误)
	// are never emitted: request bodies go through one strict decode, so the two
	// cases share a single failure path and the server cannot tell them apart
	// reliably.
	CodeBadRequest              = 40000 // 请求参数错误
	CodeVerificationCodeWrong   = 40010 // 验证码错误
	CodeVerificationCodeExpired = 40011 // 验证码已过期
	// Verification-code send throttling returns CodeRateLimited (42900) like every
	// other limiter; a dedicated 40012 is never emitted for the same reason as the
	// two codes above.
	CodeEmailDomainNotAllowed = 40020 // 邮箱域名不允许

	CodeUnauthenticated       = 40100 // 未登录
	CodeAccessTokenExpired    = 40101 // Access Token 已过期
	CodeAccessTokenInvalid    = 40102 // Access Token 无效或已被撤销
	CodeRegisterTicketInvalid = 40103 // Register-Ticket 无效或已过期
	CodeBindTicketInvalid     = 40104 // Bind-Ticket 无效或已过期
	CodePasswordInvalid       = 40105 // 密码错误
	CodeUnknownIdentifier     = 40106 // 登录邮箱不存在
	CodeLoginCodeInvalid      = 40107 // login_code 无效或已过期
	// CodeConcurrentRefresh reports a benign concurrent refresh: the presented
	// refresh token was already rotated by a sibling request within the 30s grace
	// window, and the family is preserved. Still HTTP 401 (the token is dead),
	// but distinct so the session handler can tell "the cookie's family is truly
	// gone" apart from "another tab just rotated it" — only the former should
	// clear the session cookie.
	CodeConcurrentRefresh = 40108 // 刷新请求冲突，请重试

	CodeForbidden          = 40300 // 无权限
	CodeAccountDeleted     = 40301 // 账号已注销
	CodeLarkTenantRequired = 40302 // 非 SAST 企业飞书用户

	CodeNotFound       = 40400 // 资源不存在
	CodeUserNotFound   = 40401 // 用户不存在
	CodeClientNotFound = 40402 // OAuth 客户端不存在

	CodeConflict               = 40900 // 资源已存在
	CodeEmailAlreadyRegistered = 40901 // 邮箱已被注册
	CodeStudentIDOccupied      = 40902 // 学号已被占用
	CodeIdentityOccupied       = 40903 // 第三方账号已被其他用户绑定
	CodeIdentityAlreadyBound   = 40904 // 该类型账号已绑定
	CodeIdentityLimitReached   = 40905 // 第三方邮箱绑定数量已达上限

	CodeValidationFailed  = 42200 // 业务校验失败
	CodePasswordTooShort  = 42201 // 密码长度不足
	CodePasswordUnchanged = 42202 // 新旧密码相同
	CodeAvatarRejected    = 42203 // 头像未通过内容审核

	CodeRateLimited = 42900 // 请求过于频繁

	CodeInternal              = 50000 // 服务器内部错误
	CodeEmailDeliveryFailed   = 50001 // 邮件发送失败
	CodeObjectUploadFailed    = 50002 // 对象存储上传失败
	CodeDatabaseFailed        = 50003 // 数据库错误
	CodeDependencyUnavailable = 50300 // 依赖服务暂不可用
)
