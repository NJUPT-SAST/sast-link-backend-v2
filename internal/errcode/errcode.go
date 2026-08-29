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
	// CodeCaptchaFailed is a human-verification failure on an unauthenticated write
	// endpoint: a missing or malformed Turnstile token, a token the siteverify API
	// rejects, or one issued for a different action. It is distinct from
	// CodeAlumniRequestUnavailable, which reports that the check could not be
	// performed at all - telling a submitter they failed a challenge when the channel
	// is simply misconfigured sends them to re-solve a widget forever.
	CodeCaptchaFailed = 40021 // 人机校验未通过

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
	// CodeAlumniRequestNotFound is a review action naming an account-request ticket
	// that does not exist. Separate from CodeUserNotFound because the console's
	// ticket queue and its user list are different resources, and a reviewer needs to
	// know which one the id failed to match.
	CodeAlumniRequestNotFound = 40403 // 建号申请不存在

	CodeConflict               = 40900 // 资源已存在
	CodeEmailAlreadyRegistered = 40901 // 邮箱已被注册
	CodeStudentIDOccupied      = 40902 // 学号已被占用
	CodeIdentityOccupied       = 40903 // 第三方账号已被其他用户绑定
	CodeIdentityAlreadyBound   = 40904 // 该类型账号已绑定
	CodeIdentityLimitReached   = 40905 // 第三方邮箱绑定数量已达上限
	// CodeAlumniRequestPending reports the partial unique index on alumni_requests:
	// one student ID may hold at most one ticket awaiting review. A resubmission
	// after a rejection is allowed, so this is not "you already applied" but "your
	// application is still open".
	//
	// An occupied email on that flow deliberately reuses CodeEmailAlreadyRegistered
	// (40901) rather than taking a code of its own: the outcome a client must handle
	// is identical, and errcode's rule is that the constant set is exactly what
	// clients can observe - two codes for one observable outcome is drift waiting to
	// happen.
	CodeAlumniRequestPending = 40906 // 该学号已有待审申请

	CodeValidationFailed  = 42200 // 业务校验失败
	CodePasswordTooShort  = 42201 // 密码长度不足
	CodePasswordUnchanged = 42202 // 新旧密码相同
	CodeAvatarRejected    = 42203 // 头像未通过内容审核
	// CodeAlumniRequestReviewed is a second review of a ticket that already carries a
	// verdict. 422 rather than 409: the ticket exists and the request is well formed,
	// the transition is what is refused. It is what a double-clicked approve button
	// sees, which is why the approval transaction locks the row rather than trusting
	// a prior read.
	CodeAlumniRequestReviewed = 42204 // 申请已被处理

	CodeRateLimited = 42900 // 请求过于频繁

	CodeInternal              = 50000 // 服务器内部错误
	CodeEmailDeliveryFailed   = 50001 // 邮件发送失败
	CodeObjectUploadFailed    = 50002 // 对象存储上传失败
	CodeDatabaseFailed        = 50003 // 数据库错误
	CodeDependencyUnavailable = 50300 // 依赖服务暂不可用
	// CodeAlumniRequestUnavailable means the account-request channel cannot accept a
	// submission because its human-verification dependency is absent or unreachable:
	// no Turnstile secret configured, or siteverify timing out. The endpoint refuses
	// rather than admitting the request unverified - an unauthenticated write path
	// with the challenge switched off has only the rate limiter left. Clients use it
	// to hide the entry point instead of offering a form that cannot succeed.
	CodeAlumniRequestUnavailable = 50301 // 申请通道暂不可用
)

// Messages is the canonical user-facing message for each business code. Handler
// maps reference it instead of copying the literals into their own switches,
// which is how "邮件发送失败" vs "邮件发送失败，请稍后重试" previously drifted
// (audit finding #12). A handler may still override a code's message for a
// specific surface — it then owns a comment saying why.
//
// #nosec G101 -- Localized business copy keyed by code, not credentials.
//
//nolint:gosec // Localized error copy, not credentials; G101 flags the map shape.
var Messages = map[int]string{
	CodeBadRequest:              "请求参数错误",
	CodeVerificationCodeWrong:   "验证码错误",
	CodeVerificationCodeExpired: "验证码已过期",
	CodeEmailDomainNotAllowed:   "邮箱域名不允许",
	CodeCaptchaFailed:           "人机校验未通过",

	CodeUnauthenticated:       "未登录",
	CodeAccessTokenExpired:    "Access Token 已过期",
	CodeAccessTokenInvalid:    "Access Token 无效或已被撤销",
	CodeRegisterTicketInvalid: "Register-Ticket 无效或已过期",
	CodeBindTicketInvalid:     "Bind-Ticket 无效或已过期",
	CodePasswordInvalid:       "密码错误",
	CodeUnknownIdentifier:     "登录邮箱不存在",
	CodeLoginCodeInvalid:      "login_code 无效或已过期",
	CodeConcurrentRefresh:     "刷新请求冲突，请重试",

	CodeForbidden:          "无权限",
	CodeAccountDeleted:     "账号已注销",
	CodeLarkTenantRequired: "非 SAST 企业飞书用户",

	CodeNotFound:              "资源不存在",
	CodeUserNotFound:          "用户不存在",
	CodeClientNotFound:        "OAuth 客户端不存在",
	CodeAlumniRequestNotFound: "建号申请不存在",

	CodeConflict:               "资源已存在",
	CodeEmailAlreadyRegistered: "邮箱已被注册",
	CodeStudentIDOccupied:      "学号已被占用",
	CodeIdentityOccupied:       "第三方账号已被其他用户绑定",
	CodeIdentityAlreadyBound:   "该类型账号已绑定",
	CodeIdentityLimitReached:   "第三方邮箱绑定数量已达上限",
	CodeAlumniRequestPending:   "该学号已有待审申请",

	CodeValidationFailed:      "业务校验失败",
	CodePasswordTooShort:      "密码长度不足",
	CodePasswordUnchanged:     "新旧密码相同",
	CodeAvatarRejected:        "头像未通过内容审核",
	CodeAlumniRequestReviewed: "申请已被处理",

	CodeRateLimited: "请求过于频繁",

	CodeInternal:                 "服务器内部错误",
	CodeEmailDeliveryFailed:      "邮件发送失败",
	CodeObjectUploadFailed:       "对象存储上传失败",
	CodeDatabaseFailed:           "数据库错误",
	CodeDependencyUnavailable:    "依赖服务暂不可用",
	CodeAlumniRequestUnavailable: "申请通道暂不可用",
}
