package dto

// ==================== 请求 DTO ====================

// ChangeProfileRequest 修改用户资料请求
type ChangeProfileRequest struct {
	Nickname   string `json:"nickname"`
	Department string `json:"department"`
	Intro      string `json:"intro"`
	BlogURL    string `json:"blogUrl"`
	GitHubURL  string `json:"githubUrl"`
}

// ==================== 响应 DTO ====================

// ProfileResponse 用户资料响应
type ProfileResponse struct {
	ID         int64  `json:"id"`
	UserID     int64  `json:"userId"`
	Nickname   string `json:"nickname,omitempty"`
	Department string `json:"department,omitempty"`
	Intro      string `json:"intro,omitempty"`
	Email      string `json:"email,omitempty"`
	Avatar     string `json:"avatar,omitempty"`
	BlogURL    string `json:"blogUrl,omitempty"`
	GitHubURL  string `json:"githubUrl,omitempty"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
}
