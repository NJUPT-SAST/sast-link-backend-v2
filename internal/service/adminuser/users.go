package adminuser

import (
	"context"
	"errors"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// ListUsers returns a filtered page of accounts.
//
// A read, so nothing is audited: PRD §4.13 lists only write operations, matching
// adminclient.ListClients. Soft-deleted accounts are included — the console needs
// to find one in order to restore it.
func (s Service) ListUsers(ctx context.Context, input ListUsersInput) (*ListUsersResult, error) {
	if s.Users == nil {
		return nil, newError(ErrInternal, "用户仓储未配置", nil)
	}
	page, pageSize := normalizePaging(input.Page, input.PageSize, defaultUserPageSize)
	filter := repository.AdminUserFilter{
		StudentID: input.StudentID,
		Keyword:   input.Keyword,
		Limit:     pageSize,
		Offset:    (page - 1) * pageSize,
	}
	if input.Role != "" {
		role := model.UserRole(input.Role)
		if !validRole(role) {
			return nil, newError(ErrInvalidInput, "role 取值非法", nil)
		}
		filter.Role = &role
	}
	if input.State != "" {
		state := model.UserState(input.State)
		if !validState(state) {
			return nil, newError(ErrInvalidInput, "state 取值非法", nil)
		}
		filter.State = &state
	}
	if input.Department != "" {
		department := model.Department(input.Department)
		if !department.Valid() {
			return nil, newError(ErrInvalidInput, "department 取值非法", nil)
		}
		filter.Department = &department
	}

	rows, total, err := s.Users.ListAdminUsers(ctx, filter)
	if err != nil {
		return nil, newError(ErrInternal, "查询用户列表失败", err)
	}
	items := make([]UserListItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, userListItem(row))
	}
	return &ListUsersResult{Users: items, Total: total, Page: page, PageSize: pageSize}, nil
}

// GetUser returns one account with its profile and bindings.
func (s Service) GetUser(ctx context.Context, userID int64) (*UserDetail, error) {
	if s.Users == nil {
		return nil, newError(ErrInternal, "用户仓储未配置", nil)
	}
	if userID <= 0 {
		return nil, newError(ErrNotFound, "用户不存在", nil)
	}
	user, err := s.Users.FindByID(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrNotFound, "用户不存在", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询用户详情失败", err)
	}
	if user == nil {
		return nil, newError(ErrNotFound, "用户不存在", nil)
	}
	detail := userDetail(user)
	return &detail, nil
}

// UpdateUser applies a partial administrative edit.
//
// Two guards beyond field validation, neither of which the written contract
// specifies:
//
// An administrator cannot change their own role. Self-demotion is unrecoverable
// through this API — the endpoint that would undo it is the one just given up —
// so it needs a second administrator or direct database access to fix.
//
// The last active administrator cannot be demoted. That check is a count over
// other rows, so it lives in the repository transaction where it can be
// serialized; doing it here would let two concurrent demotions both observe a
// safe count.
func (s Service) UpdateUser(ctx context.Context, input UpdateUserInput) (*UpdateUserResult, error) {
	if s.Users == nil {
		return nil, newError(ErrInternal, "用户仓储未配置", nil)
	}
	if input.UserID <= 0 {
		return nil, newError(ErrNotFound, "用户不存在", nil)
	}
	validated, err := validateUpdate(input)
	if err != nil {
		s.auditUpdate(ctx, input, false, errorCode(err), nil)
		return nil, err
	}
	if len(validated.changed) == 0 {
		emptyErr := newError(ErrInvalidInput, "没有需要更新的字段", nil)
		s.auditUpdate(ctx, input, false, errorCode(emptyErr), nil)
		return nil, emptyErr
	}

	current, err := s.loadTarget(ctx, input.UserID)
	if err != nil {
		s.auditUpdate(ctx, input, false, errorCode(err), nil)
		return nil, err
	}
	// A closed account is edited by restoring it first. UpdateAdminUser excludes
	// them in SQL as well; checking here is what turns that into a 422 explaining
	// the order rather than a 404 on a user the console can see.
	if current.State == model.UserStateDeleted {
		closedErr := newError(ErrStateConflict, "用户已注销，请先恢复后再编辑", nil)
		s.auditUpdate(ctx, input, false, errorCode(closedErr), nil)
		return nil, closedErr
	}

	roleChanged := validated.role != nil && *validated.role != current.Role
	if roleChanged && input.UserID == input.AdminUserID {
		selfErr := newError(ErrProtected, "不可修改自己的角色", nil)
		s.auditUpdate(ctx, input, false, errorCode(selfErr), nil)
		return nil, selfErr
	}
	// Only a demotion can remove an administrator here: state can no longer be set to
	// is_deleted through this path, so the role is the single way an admin stops being
	// one. The repository still re-checks under a lock — this flag only says whether
	// the check is needed.
	guardLastAdmin := roleChanged && current.Role == model.UserRoleAdmin

	entries, err := s.Users.UpdateAdminUser(ctx, input.UserID, repository.AdminUserUpdate{
		Name:        validated.name,
		PhoneNumber: validated.phoneNumber,
		QQNumber:    validated.qqNumber,
		StudentID:   validated.studentID,
		Major:       validated.major,
		College:     validated.college,
		LoginEmail:  validated.loginEmail,
		Role:        validated.role,
		State:       validated.state,
		EmailType:   validated.emailType,
		// The role is what invalidates a session: an access token carries the role it was
		// signed with, and although the auth middleware reads the role from the database
		// on every request, a demoted account's live refresh tokens would otherwise keep
		// minting tokens for a session the administrator meant to end.
	}, guardLastAdmin, roleChanged, s.now())
	if err != nil {
		mapped := s.mapWriteError(ctx, err)
		s.auditUpdate(ctx, input, false, errorCode(mapped), validated.changed)
		return nil, mapped
	}
	s.deliverBlacklist(ctx, entries, s.now())
	s.auditUpdate(ctx, input, true, 0, validated.changed)
	return &UpdateUserResult{ChangedFields: validated.changed, RevokedSessions: roleChanged}, nil
}

// DeleteUser closes an account and cuts every session it holds.
func (s Service) DeleteUser(ctx context.Context, input TargetUserInput) error {
	if s.Users == nil {
		return newError(ErrInternal, "用户仓储未配置", nil)
	}
	if input.UserID <= 0 {
		return newError(ErrNotFound, "用户不存在", nil)
	}
	// Closing your own account through the admin console locks you out of the very
	// endpoint that would reopen it, so it is refused for the same reason as
	// self-demotion.
	if input.UserID == input.AdminUserID {
		err := newError(ErrProtected, "不可注销自己的账号", nil)
		s.auditTarget(ctx, input, actionDeleteUser, false, errorCode(err))
		return err
	}
	entries, err := s.Users.SoftDeleteAndRevokeSessions(ctx, input.UserID, s.now())
	if err != nil {
		mapped := s.mapDeleteError(ctx, err)
		s.auditTarget(ctx, input, actionDeleteUser, false, errorCode(mapped))
		return mapped
	}
	s.deliverBlacklist(ctx, entries, s.now())
	s.auditTarget(ctx, input, actionDeleteUser, true, 0)
	return nil
}

// RestoreUser reopens a closed account at the njupter state.
func (s Service) RestoreUser(ctx context.Context, input TargetUserInput) error {
	if s.Users == nil {
		return newError(ErrInternal, "用户仓储未配置", nil)
	}
	if input.UserID <= 0 {
		return newError(ErrNotFound, "用户不存在", nil)
	}
	err := s.Users.RestoreUser(ctx, input.UserID)
	if err != nil {
		var mapped error
		switch {
		case errors.Is(err, repository.ErrNotFound):
			mapped = newError(ErrNotFound, "用户不存在", nil)
		case errors.Is(err, repository.ErrStateConflict):
			mapped = newError(ErrStateConflict, "用户未被注销，无需恢复", nil)
		default:
			mapped = newError(ErrInternal, "恢复用户失败", err)
		}
		s.auditTarget(ctx, input, actionRestoreUser, false, errorCode(mapped))
		return mapped
	}
	s.auditTarget(ctx, input, actionRestoreUser, true, 0)
	return nil
}

// loadTarget reads the account an edit is about to change.
func (s Service) loadTarget(ctx context.Context, userID int64) (*model.User, error) {
	user, err := s.Users.FindByID(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrNotFound, "用户不存在", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询用户失败", err)
	}
	if user == nil {
		return nil, newError(ErrNotFound, "用户不存在", nil)
	}
	return user, nil
}

// mapWriteError translates a repository failure from the update path.
func (s Service) mapWriteError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return newError(ErrNotFound, "用户不存在", nil)
	case errors.Is(err, repository.ErrLastAdmin):
		return newError(ErrProtected, "系统中至少需要保留一名管理员", nil)
	}
	return s.mapUniqueViolation(ctx, err, "更新用户失败")
}

// mapDeleteError translates a repository failure from the soft-delete path.
func (s Service) mapDeleteError(_ context.Context, err error) error {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return newError(ErrNotFound, "用户不存在", nil)
	case errors.Is(err, repository.ErrStateConflict):
		return newError(ErrStateConflict, "用户已注销", nil)
	case errors.Is(err, repository.ErrLastAdmin):
		return newError(ErrProtected, "系统中至少需要保留一名管理员", nil)
	}
	return newError(ErrInternal, "注销用户失败", err)
}

func (s Service) auditUpdate(
	ctx context.Context,
	input UpdateUserInput,
	success bool,
	errCode int,
	changed []string,
) {
	// Field names only, never their values: a login_email or student_id written into
	// audit detail outlives the request and is readable by every administrator.
	detail := map[string]any{}
	if len(changed) > 0 {
		detail["changed_fields"] = changed
	}
	s.audit(ctx, input.AdminUserID, actionUpdateUser, input.UserID,
		success, errCode, input.ClientIP, input.UserAgent, detail)
}

func (s Service) auditTarget(
	ctx context.Context,
	input TargetUserInput,
	action string,
	success bool,
	errCode int,
) {
	s.audit(ctx, input.AdminUserID, action, input.UserID,
		success, errCode, input.ClientIP, input.UserAgent, nil)
}

// errorCode extracts the business code of a typed service error for the audit
// trail; anything else is recorded as an internal failure.
func errorCode(err error) int {
	var serviceErr *Error
	if errors.As(err, &serviceErr) && serviceErr.Code != 0 {
		return serviceErr.Code
	}
	return ErrInternal.Code
}
