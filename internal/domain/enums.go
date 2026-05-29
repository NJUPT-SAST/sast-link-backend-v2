package domain

// UserRole 用户角色
type UserRole string

const (
	UserRoleFreshman UserRole = "freshman"
	UserRoleMember   UserRole = "member"
	UserRoleLecturer UserRole = "lecturer"
	UserRoleAdmin    UserRole = "admin"
)

// Department 部门
type Department string

const (
	DepartmentSoftware Department = "software"
	DepartmentMedia    Department = "media"
)

// LoginMethod 第三方登录方式
type LoginMethod string

const (
	LoginMethodGitHub    LoginMethod = "github"
	LoginMethodLark      LoginMethod = "lark"
	LoginMethodOtherMail LoginMethod = "other_mail"
)

// UserState 用户状态
type UserState string

const (
	UserStateIsDeleted   UserState = "is_deleted"
	UserStateOnSAST      UserState = "on-sast"
	UserStateRetiredSAST UserState = "retired-sast"
	UserStateNJUPter     UserState = "njupter"
)

// EmailType 注册邮箱类型
type EmailType string

const (
	EmailTypeSAST  EmailType = "sast_email"
	EmailTypeNJUPT EmailType = "njupt_email"
)
