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

// ClientType OAuth 客户端类型
type ClientType string

// Client types.
const (
	ClientTypeFirstParty ClientType = "first_party"
	ClientTypeThirdParty ClientType = "third_party"
)

// College 学院
type College string

// College values — matches college_enum in DB schema.
const (
	CollegeBell             College = "贝尔英才学院"
	CollegeTelecom          College = "通信与信息工程学院"
	CollegeElectroOptics    College = "电光柔学院"
	CollegeIC               College = "集成电路科学与工程学院（产教融合学院）"
	CollegeCS               College = "计算机学院、软件学院、网络空间安全学院"
	CollegeAutomation       College = "自动化学院"
	CollegeAI               College = "人工智能学院"
	CollegeMaterials        College = "材料科学与工程学院"
	CollegeChemBio          College = "化学与生命科学学院"
	CollegeIoT              College = "物联网学院"
	CollegeScience          College = "理学院"
	CollegeModernPost       College = "现代邮政学院、智慧交通学院"
	CollegeDigitalMedia     College = "数字媒体与设计艺术学院"
	CollegeManagement       College = "管理学院"
	CollegeEconomics        College = "经济学院"
	CollegeSociology        College = "社会与人口学院、社会工作学院"
	CollegeForeignLanguages College = "外国语学院"
	CollegeEducation        College = "教育科学与技术学院"
	CollegePortland         College = "波特兰学院"
	CollegeOther            College = "其他"
)

// ValidCollegeValues returns all valid college enum values.
func ValidCollegeValues() []College {
	return []College{
		CollegeBell, CollegeTelecom, CollegeElectroOptics, CollegeIC,
		CollegeCS, CollegeAutomation, CollegeAI, CollegeMaterials,
		CollegeChemBio, CollegeIoT, CollegeScience, CollegeModernPost,
		CollegeDigitalMedia, CollegeManagement, CollegeEconomics,
		CollegeSociology, CollegeForeignLanguages, CollegeEducation,
		CollegePortland, CollegeOther,
	}
}
