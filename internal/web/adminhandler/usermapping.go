package adminhandler

import (
	"errors"
	"net/http"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminuser"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

var errInvalidQueryParameter = errors.New("query parameter is not valid")

// adminUserDTO is one user row on the wire. Written out field by field rather than
// serializing model.User, which carries the password hash: a response type with no
// such field cannot leak it no matter how the model changes later.
type adminUserDTO struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	StudentID   string    `json:"student_id"`
	LoginEmail  string    `json:"login_email"`
	Role        string    `json:"role"`
	State       string    `json:"state"`
	EmailType   string    `json:"email_type"`
	PhoneNumber string    `json:"phone_number"`
	QQNumber    string    `json:"qq_number"`
	College     string    `json:"college"`
	Major       string    `json:"major"`
	Department  *string   `json:"department"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type adminUserListResponse struct {
	Users    []adminUserDTO `json:"users"`
	Total    int64          `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
}

// userDetailDTO is one full user record. Same reasoning as adminUserDTO, plus the
// profile and identity halves.
type userDetailDTO struct {
	ID          int64             `json:"id"`
	Name        string            `json:"name"`
	LoginEmail  string            `json:"login_email"`
	Role        string            `json:"role"`
	State       string            `json:"state"`
	EmailType   string            `json:"email_type"`
	PhoneNumber string            `json:"phone_number"`
	QQNumber    string            `json:"qq_number"`
	StudentID   string            `json:"student_id"`
	College     string            `json:"college"`
	Major       string            `json:"major"`
	Profile     *userProfileDTO   `json:"profile"`
	Identities  []userIdentityDTO `json:"identities"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type userProfileDTO struct {
	Nickname   *string   `json:"nickname"`
	Department *string   `json:"department"`
	Intro      *string   `json:"intro"`
	Email      *string   `json:"email"`
	Avatar     *string   `json:"avatar"`
	BlogURL    *string   `json:"blog_url"`
	GitHubURL  *string   `json:"github_url"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// userIdentityDTO omits the stored provider access and refresh tokens: the console
// displays bindings, it does not hand out the credentials behind them.
//
// identity_data is omitted for the same reason. It holds the provider's whole user
// object — docs/psql-db-design.md documents the Lark payload as carrying mobile,
// email, enterprise_email and employee_no — and these endpoints are readable by
// lecturers, not just administrators. Listing which accounts a user has bound does
// not require handing over the personal contact details behind them. If the console
// ever needs a field from it, forward that field, not the blob.
type userIdentityDTO struct {
	ID             int64      `json:"id"`
	Provider       string     `json:"provider"`
	ProviderID     string     `json:"provider_id"`
	TokenExpiresAt *time.Time `json:"token_expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type auditLogDTO struct {
	ID         int64       `json:"id"`
	UserID     *int64      `json:"user_id"`
	UserName   *string     `json:"user_name"`
	Action     string      `json:"action"`
	Resource   string      `json:"resource"`
	ResourceID *string     `json:"resource_id"`
	Detail     model.JSONB `json:"detail"`
	ClientIP   *string     `json:"client_ip"`
	UserAgent  *string     `json:"user_agent"`
	Success    bool        `json:"success"`
	ErrCode    *int        `json:"err_code"`
	CreatedAt  time.Time   `json:"created_at"`
}

type auditLogListResponse struct {
	Logs     []auditLogDTO `json:"logs"`
	Total    int64         `json:"total"`
	Page     int           `json:"page"`
	PageSize int           `json:"page_size"`
}

func mapAdminUser(user adminuser.UserListItem) adminUserDTO {
	return adminUserDTO{
		ID:          user.ID,
		Name:        user.Name,
		StudentID:   user.StudentID,
		LoginEmail:  user.LoginEmail,
		Role:        user.Role,
		State:       user.State,
		EmailType:   user.EmailType,
		PhoneNumber: user.PhoneNumber,
		QQNumber:    user.QQNumber,
		College:     user.College,
		Major:       user.Major,
		Department:  user.Department,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}
}

func mapUserDetail(detail adminuser.UserDetail) userDetailDTO {
	dto := userDetailDTO{
		ID:          detail.ID,
		Name:        detail.Name,
		LoginEmail:  detail.LoginEmail,
		Role:        detail.Role,
		State:       detail.State,
		EmailType:   detail.EmailType,
		PhoneNumber: detail.PhoneNumber,
		QQNumber:    detail.QQNumber,
		StudentID:   detail.StudentID,
		College:     detail.College,
		Major:       detail.Major,
		Identities:  make([]userIdentityDTO, 0, len(detail.Identities)),
		CreatedAt:   detail.CreatedAt,
		UpdatedAt:   detail.UpdatedAt,
	}
	if detail.Profile != nil {
		dto.Profile = &userProfileDTO{
			Nickname:   detail.Profile.Nickname,
			Department: detail.Profile.Department,
			Intro:      detail.Profile.Intro,
			Email:      detail.Profile.Email,
			Avatar:     detail.Profile.Avatar,
			BlogURL:    detail.Profile.BlogURL,
			GitHubURL:  detail.Profile.GitHubURL,
			CreatedAt:  detail.Profile.CreatedAt,
			UpdatedAt:  detail.Profile.UpdatedAt,
		}
	}
	for _, identity := range detail.Identities {
		dto.Identities = append(dto.Identities, userIdentityDTO{
			ID:             identity.ID,
			Provider:       identity.Provider,
			ProviderID:     identity.ProviderID,
			TokenExpiresAt: identity.TokenExpiresAt,
			CreatedAt:      identity.CreatedAt,
			UpdatedAt:      identity.UpdatedAt,
		})
	}
	return dto
}

func mapAuditLog(entry adminuser.AuditLogItem) auditLogDTO {
	return auditLogDTO{
		ID:         entry.ID,
		UserID:     entry.UserID,
		UserName:   entry.UserName,
		Action:     entry.Action,
		Resource:   entry.Resource,
		ResourceID: entry.ResourceID,
		Detail:     entry.Detail,
		ClientIP:   entry.ClientIP,
		UserAgent:  entry.UserAgent,
		Success:    entry.Success,
		ErrCode:    entry.ErrCode,
		CreatedAt:  entry.CreatedAt,
	}
}

// mapUserServiceError converts a typed adminuser error into the HTTP envelope.
//
// Separate from mapServiceError rather than shared: that one matches
// *adminclient.Error and reports "OAuth 客户端不存在" for a not-found, which is the
// wrong noun and the wrong business code here.
func mapUserServiceError(err error) error {
	var serviceErr *adminuser.Error
	if !errors.As(err, &serviceErr) {
		return internalError()
	}
	status := http.StatusInternalServerError
	message := "服务器内部错误"
	switch serviceErr.Kind {
	case adminuser.KindInvalidInput:
		status = http.StatusBadRequest
		// The service's messages are literals naming which rule was broken, never echoes
		// of submitted values, so they are safe to return verbatim and are what makes a
		// rejected edit actionable.
		message = serviceErr.Message
	case adminuser.KindNotFound:
		status = http.StatusNotFound
		message = "用户不存在"
	case adminuser.KindConflict:
		status = http.StatusConflict
		message = serviceErr.Message
	case adminuser.KindStateConflict:
		// 422 rather than 409: the request is well formed and the target exists, it is
		// the transition that the account's current state does not allow.
		status = http.StatusUnprocessableEntity
		message = serviceErr.Message
	case adminuser.KindProtected:
		// 403 rather than 400: the request is well formed and the administrator is
		// authorized, but the target is not theirs to change. The message names the rule,
		// since a bare "forbidden" would look like a role problem.
		status = http.StatusForbidden
		message = serviceErr.Message
	case adminuser.KindInternal:
	}
	code := serviceErr.Code
	if code == 0 {
		code = errcode.CodeInternal
	}
	return &response.BusinessError{HTTPStatus: status, Code: code, Message: message}
}

func userNotFound() error {
	return &response.BusinessError{
		HTTPStatus: http.StatusNotFound,
		Code:       errcode.CodeUserNotFound,
		Message:    "用户不存在",
	}
}
