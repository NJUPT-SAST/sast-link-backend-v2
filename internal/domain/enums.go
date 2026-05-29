package domain

// UserRole 用户角色
type UserRole string

// User roles.
const (
	UserRoleFreshman UserRole = "freshman"
	UserRoleMember   UserRole = "member"
	UserRoleLecturer UserRole = "lecturer"
	UserRoleAdmin    UserRole = "admin"
)

// Department 部门
type Department string

// Departments.
const (
	DepartmentSoftware Department = "software"
	DepartmentMedia    Department = "media"
)

// LoginMethod 第三方登录方式
type LoginMethod string

// Login methods.
const (
	LoginMethodGitHub    LoginMethod = "github"
	LoginMethodLark      LoginMethod = "lark"
	LoginMethodOtherMail LoginMethod = "other_mail"
)

// UserState 用户状态
type UserState string

// User states.
const (
	UserStateIsDeleted   UserState = "is_deleted"
	UserStateOnSAST      UserState = "on-sast"
	UserStateRetiredSAST UserState = "retired-sast"
	UserStateNJUPter     UserState = "njupter"
)

// EmailType 注册邮箱类型
type EmailType string

// Email types.
const (
	EmailTypeSAST  EmailType = "sast_email"
	EmailTypeNJUPT EmailType = "njupt_email"
)
