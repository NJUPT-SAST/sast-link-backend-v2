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

// adminUserDTO is one user row on the wire. Written out field by field rather
// than serializing model.User, which carries the password hash: a response type
// with no such field cannot leak it no matter how the model changes later.
//
// The phone field is a pointer with omitempty: only an admin sees it; any other
// role reading the list (a lecturer) gets the directory view, where the field is
// absent rather than empty — "not disclosed" must not read as "not filled in".
// The rule is "admin or hidden", so a future role defaults to the restricted
// view. qq_number carries no such restriction and stays a plain field.
type adminUserDTO struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	StudentID   string  `json:"student_id"`
	LoginEmail  string  `json:"login_email"`
	Role        string  `json:"role"`
	State       string  `json:"state"`
	EmailType   string  `json:"email_type"`
	PhoneNumber *string `json:"phone_number,omitempty"`
	QQNumber    string  `json:"qq_number"`
	College     string  `json:"college"`
	Major       string  `json:"major"`
	Department  *string `json:"department"`
	// ProfileNeedsCompletion marks an account still carrying values imported from
	// the previous database, and IncompleteFields names them. Both let the console
	// show and work through the backlog; combine with ?needs_completion=true to
	// list only those accounts.
	ProfileNeedsCompletion bool     `json:"profile_needs_completion"`
	IncompleteFields       []string `json:"incomplete_fields"`
	// StateManual says whether state above was hand-written (and therefore pins
	// the row out of the derived-state machine) or derived. The console needs it
	// to decide whether state_auto is the right next request.
	StateManual bool      `json:"state_manual"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type adminUserListResponse struct {
	Users    []adminUserDTO `json:"users"`
	Total    int64          `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
}

// batchUsersResponse is the batch user-detail read: the same record shape as
// GET /admin/users/:id, in request order, with missing ids absent.
type batchUsersResponse struct {
	Users []userDetailDTO `json:"users"`
}

// roleUpdateResultDTO is one id's outcome of a batch role change. omitempty
// keeps a success from carrying an empty reason and a failure from carrying a
// role that was never applied.
type roleUpdateResultDTO struct {
	ID      int64  `json:"id"`
	Success bool   `json:"success"`
	Role    string `json:"role,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type batchRoleUpdateResponse struct {
	Results []roleUpdateResultDTO `json:"results"`
}

// userDetailDTO is one full user record. Same reasoning as adminUserDTO, plus the
// profile and identity halves. The phone field follows the same role rule as the
// list: present for an admin, absent for every other role.
type userDetailDTO struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	LoginEmail  string  `json:"login_email"`
	Role        string  `json:"role"`
	State       string  `json:"state"`
	EmailType   string  `json:"email_type"`
	PhoneNumber *string `json:"phone_number,omitempty"`
	QQNumber    string  `json:"qq_number"`
	StudentID   string  `json:"student_id"`
	College     string  `json:"college"`
	Major       string  `json:"major"`
	// See adminUserDTO.
	ProfileNeedsCompletion bool              `json:"profile_needs_completion"`
	IncompleteFields       []string          `json:"incomplete_fields"`
	StateManual            bool              `json:"state_manual"`
	Profile                *userProfileDTO   `json:"profile"`
	Identities             []userIdentityDTO `json:"identities"`
	CreatedAt              time.Time         `json:"created_at"`
	UpdatedAt              time.Time         `json:"updated_at"`
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

// userIdentityDTO omits the stored provider access and refresh tokens and the
// identity_data blob, which can carry personal contact details: these endpoints
// are readable by lecturers, not just administrators, and listing bindings does
// not require handing over the credentials or details behind them.
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
	// ActorClientID is the OAuth client whose credential authorized the action. null
	// means none did — an unauthenticated flow, a background worker, or a row written
	// before the column existed.
	ActorClientID *string   `json:"actor_client_id"`
	CreatedAt     time.Time `json:"created_at"`
}

type auditLogListResponse struct {
	Logs     []auditLogDTO `json:"logs"`
	Total    int64         `json:"total"`
	Page     int           `json:"page"`
	PageSize int           `json:"page_size"`
}

// mapAdminUser maps one list row. The phone field rides on the caller's role:
// an admin sees the stored value (an empty string stays an empty string — it is
// the true "not filled in" state), every other role gets nil, which drops the
// field from the response entirely. qq_number is visible to every role.
func mapAdminUser(user adminuser.UserListItem, role string) adminUserDTO {
	isAdmin := role == string(model.UserRoleAdmin)
	var phoneNumber *string
	if isAdmin {
		phoneNumber = &user.PhoneNumber
	}
	return adminUserDTO{
		ID:          user.ID,
		Name:        user.Name,
		StudentID:   user.StudentID,
		LoginEmail:  user.LoginEmail,
		Role:        user.Role,
		State:       user.State,
		EmailType:   user.EmailType,
		PhoneNumber: phoneNumber,
		QQNumber:    user.QQNumber,
		College:     user.College,
		Major:       user.Major,
		Department:  user.Department,

		ProfileNeedsCompletion: user.ProfileNeedsCompletion,
		IncompleteFields:       user.IncompleteFields,
		StateManual:            user.StateManual,

		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

// mapUserDetail maps one full record. Same phone rule as mapAdminUser: an admin
// sees the stored value (an empty string stays an empty string), every other role
// gets nil so the field is absent. qq_number, identities and the profile ride
// along for every role — the same view the detail endpoint always offered before
// the phone restriction.
func mapUserDetail(detail adminuser.UserDetail, role string) userDetailDTO {
	isAdmin := role == string(model.UserRoleAdmin)
	var phoneNumber *string
	if isAdmin {
		phoneNumber = &detail.PhoneNumber
	}
	dto := userDetailDTO{
		ID:          detail.ID,
		Name:        detail.Name,
		LoginEmail:  detail.LoginEmail,
		Role:        detail.Role,
		State:       detail.State,
		EmailType:   detail.EmailType,
		PhoneNumber: phoneNumber,
		QQNumber:    detail.QQNumber,
		StudentID:   detail.StudentID,
		College:     detail.College,
		Major:       detail.Major,

		ProfileNeedsCompletion: detail.ProfileNeedsCompletion,
		IncompleteFields:       detail.IncompleteFields,
		StateManual:            detail.StateManual,

		Identities: make([]userIdentityDTO, 0, len(detail.Identities)),
		CreatedAt:  detail.CreatedAt,
		UpdatedAt:  detail.UpdatedAt,
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
		ID:            entry.ID,
		UserID:        entry.UserID,
		UserName:      entry.UserName,
		Action:        entry.Action,
		Resource:      entry.Resource,
		ResourceID:    entry.ResourceID,
		Detail:        entry.Detail,
		ClientIP:      entry.ClientIP,
		UserAgent:     entry.UserAgent,
		Success:       entry.Success,
		ErrCode:       entry.ErrCode,
		ActorClientID: entry.ActorClientID,
		CreatedAt:     entry.CreatedAt,
	}
}

// mapUserServiceError converts a typed adminuser error into the HTTP envelope.
// Separate from mapServiceError rather than shared: that one matches
// *adminclient.Error with the client not-found noun and business code.
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
		// The service's messages are literals naming which rule was broken, never
		// echoes of submitted values, so they are safe to return verbatim.
		message = serviceErr.Message
	case adminuser.KindNotFound:
		status = http.StatusNotFound
		message = "用户不存在"
	case adminuser.KindConflict:
		status = http.StatusConflict
		message = serviceErr.Message
	case adminuser.KindStateConflict:
		// 422 rather than 409: the request is well formed and the target exists; the
		// transition is what the account's current state does not allow.
		status = http.StatusUnprocessableEntity
		message = serviceErr.Message
	case adminuser.KindProtected:
		// 403 rather than 400: the request is well formed and the administrator is
		// authorized, but the target is not theirs to change; the message names the
		// rule.
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
