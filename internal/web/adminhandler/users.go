package adminhandler

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminuser"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/webutil"
)

// principalRole returns the caller's role for the role-scoped field views. Every
// route that calls it sits behind RequireAuth, so a principal is always present;
// a missing one is a wiring mistake and yields "" — the restrictive view —
// rather than an unauthorized disclosure.
func principalRole(c *gin.Context) string {
	principal, _ := middleware.PrincipalFrom(c)
	return principal.Role
}

// ListUsers returns a filtered page of accounts.
func (h Handler) ListUsers(c *gin.Context) {
	page, pageSize, err := web.ParsePaging(c)
	if err != nil {
		response.Error(c, badRequest())
		return
	}
	// Tri-state: absent means "no filter". An unrecognized value is a 400 rather
	// than false, since needs_completion=ture would otherwise list the healthy
	// accounts and look like it worked.
	needsCompletion, err := parseOptionalBool(c.Query("needs_completion"))
	if err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Users.ListUsers(c.Request.Context(), adminuser.ListUsersInput{
		Page:            page,
		PageSize:        pageSize,
		Role:            c.Query("role"),
		State:           c.Query("state"),
		Department:      c.Query("department"),
		StudentID:       c.Query("student_id"),
		Keyword:         c.Query("keyword"),
		NeedsCompletion: needsCompletion,
	})
	if err != nil {
		response.Error(c, mapUserServiceError(err))
		return
	}
	items := make([]adminUserDTO, 0, len(result.Users))
	// The contact fields on the list ride on the caller's role (mapAdminUser): a
	// lecturer may read the list but not the contact fields on it.
	for _, user := range result.Users {
		items = append(items, mapAdminUser(user, principalRole(c)))
	}
	response.Ok(c, adminUserListResponse{
		Users:    items,
		Total:    result.Total,
		Page:     result.Page,
		PageSize: result.PageSize,
	})
}

// createUserRequest is the body of POST /admin/users.
//
// Optional fields default instead of staying unchanged because a new account has
// no prior value (college to "其他", major to "", role to member, state to
// retired_sast). personal_email, when set, is bound as an other_mail identity in
// the same transaction, skipping the email verification of self-service binding.
type createUserRequest struct {
	Name          string  `json:"name"`
	PhoneNumber   string  `json:"phone_number"`
	QQNumber      string  `json:"qq_number"`
	StudentID     string  `json:"student_id"`
	Major         *string `json:"major"`
	College       *string `json:"college"`
	LoginEmail    string  `json:"login_email"`
	PersonalEmail *string `json:"personal_email"`
	Role          *string `json:"role"`
	State         *string `json:"state"`
}

// createdUserDTO returns the initial password. The plaintext is not stored, so
// the administrator must copy it from this response to pass to the member.
type createdUserDTO struct {
	ID              int64  `json:"id"`
	LoginEmail      string `json:"login_email"`
	InitialPassword string `json:"initial_password"`
}

// CreateUser creates an account. When personal_email is set, it binds the
// address as an other_mail identity in the same transaction.
func (h Handler) CreateUser(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	var req createUserRequest
	if err := webutil.DecodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Users.CreateUser(c.Request.Context(), adminuser.CreateUserInput{
		Name:          req.Name,
		PhoneNumber:   req.PhoneNumber,
		QQNumber:      req.QQNumber,
		StudentID:     req.StudentID,
		Major:         req.Major,
		College:       req.College,
		LoginEmail:    req.LoginEmail,
		PersonalEmail: req.PersonalEmail,
		Role:          req.Role,
		State:         req.State,
		AdminUserID:   principal.UserID,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapUserServiceError(err))
		return
	}
	response.Ok(c, createdUserDTO{
		ID:              result.UserID,
		LoginEmail:      result.LoginEmail,
		InitialPassword: result.InitialPassword,
	})
}

// GetUser returns one account with its profile and bindings.
func (h Handler) GetUser(c *gin.Context) {
	userID, ok := web.ParsePositiveID(c.Param("id"))
	if !ok {
		// A non-numeric or non-positive segment names no user, so it gets the same 404
		// as a missing one rather than a 400 that distinguishes the two.
		response.Error(c, userNotFound())
		return
	}
	detail, err := h.Users.GetUser(c.Request.Context(), userID)
	if err != nil {
		response.Error(c, mapUserServiceError(err))
		return
	}
	// The phone field on the record rides on the caller's role (mapUserDetail).
	response.Ok(c, mapUserDetail(*detail, principalRole(c)))
}

// updateUserRequest is a partial administrative edit. Pointers so an omitted
// field is left alone rather than read as "clear it". There is no password,
// token_version or profile field: a credential rewrite is not an edit, the
// version counter is the service's to bump, and display fields belong to the
// user's own PUT /user/profile. The strict decoder turns an attempt to send one
// into a 400.
type updateUserRequest struct {
	Name        *string `json:"name"`
	PhoneNumber *string `json:"phone_number"`
	QQNumber    *string `json:"qq_number"`
	StudentID   *string `json:"student_id"`
	College     *string `json:"college"`
	Major       *string `json:"major"`
	LoginEmail  *string `json:"login_email"`
	Role        *string `json:"role"`
	State       *string `json:"state"`
	EmailType   *string `json:"email_type"`
}

// UpdateUser applies a partial administrative edit.
func (h Handler) UpdateUser(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	userID, ok := web.ParsePositiveID(c.Param("id"))
	if !ok {
		response.Error(c, userNotFound())
		return
	}
	var req updateUserRequest
	if err := webutil.DecodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Users.UpdateUser(c.Request.Context(), adminuser.UpdateUserInput{
		UserID:        userID,
		Name:          req.Name,
		PhoneNumber:   req.PhoneNumber,
		QQNumber:      req.QQNumber,
		StudentID:     req.StudentID,
		Major:         req.Major,
		College:       req.College,
		LoginEmail:    req.LoginEmail,
		Role:          req.Role,
		State:         req.State,
		EmailType:     req.EmailType,
		AdminUserID:   principal.UserID,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapUserServiceError(err))
		return
	}
	message := "用户信息更新成功"
	if result.RevokedSessions {
		// Say so: a role change cut every session the user held.
		message = "用户信息更新成功，已撤销该用户的全部 Token"
	}
	response.Ok(c, messageResponse{Message: message})
}

// GetUsersByIDs returns the full records of the requested user ids, in request
// order, with duplicates collapsed. The ids arrive comma-separated so a batch of
// up to 100 stays well inside URL limits, and a GET keeps the permission surface
// identical to GET /admin/users/:id.
func (h Handler) GetUsersByIDs(c *gin.Context) {
	ids, ok := parseIDList(c.Query("ids"))
	if !ok {
		response.Error(c, badRequest())
		return
	}
	users, err := h.Users.GetUsersByIDs(c.Request.Context(), adminuser.GetUsersByIDsInput{IDs: ids})
	if err != nil {
		response.Error(c, mapUserServiceError(err))
		return
	}
	// The phone field on each record rides on the caller's role (mapUserDetail).
	items := make([]userDetailDTO, 0, len(users))
	for _, user := range users {
		items = append(items, mapUserDetail(user, principalRole(c)))
	}
	response.Ok(c, batchUsersResponse{Users: items})
}

// parseIDList splits a comma-separated id list. A blank list, a blank segment
// or a non-numeric segment is rejected as a whole: silently dropping "abc"
// from "1,abc,2" would return a page the caller cannot line up with its input.
func parseIDList(raw string) ([]int64, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, false
	}
	segments := strings.Split(raw, ",")
	ids := make([]int64, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return nil, false
		}
		id, err := strconv.ParseInt(segment, 10, 64)
		if err != nil || id <= 0 {
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, true
}

// batchRoleUpdateRequest is the body of the batch role-change endpoint.
type batchRoleUpdateRequest struct {
	IDs  []int64 `json:"ids"`
	Role string  `json:"role"`
}

// UpdateUsersRole applies one role change to every listed user and reports the
// per-item outcome, so the caller can retry or alert on the failures.
func (h Handler) UpdateUsersRole(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	var req batchRoleUpdateRequest
	if err := webutil.DecodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Users.UpdateUserRoles(c.Request.Context(), adminuser.UpdateUserRolesInput{
		IDs:           req.IDs,
		Role:          req.Role,
		AdminUserID:   principal.UserID,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapUserServiceError(err))
		return
	}
	items := make([]roleUpdateResultDTO, 0, len(result.Results))
	for _, item := range result.Results {
		items = append(items, roleUpdateResultDTO{
			ID:      item.ID,
			Success: item.Success,
			Role:    item.Role,
			Reason:  item.Reason,
		})
	}
	response.Ok(c, batchRoleUpdateResponse{Results: items})
}

// DeleteUser closes an account and cuts every session it holds.
func (h Handler) DeleteUser(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	userID, ok := web.ParsePositiveID(c.Param("id"))
	if !ok {
		response.Error(c, userNotFound())
		return
	}
	err := h.Users.DeleteUser(c.Request.Context(), adminuser.TargetUserInput{
		UserID:        userID,
		AdminUserID:   principal.UserID,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapUserServiceError(err))
		return
	}
	response.Ok(c, messageResponse{Message: "用户已注销"})
}

// RestoreUser reopens a closed account.
func (h Handler) RestoreUser(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	userID, ok := web.ParsePositiveID(c.Param("id"))
	if !ok {
		response.Error(c, userNotFound())
		return
	}
	err := h.Users.RestoreUser(c.Request.Context(), adminuser.TargetUserInput{
		UserID:        userID,
		AdminUserID:   principal.UserID,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapUserServiceError(err))
		return
	}
	response.Ok(c, messageResponse{Message: "用户已恢复"})
}
