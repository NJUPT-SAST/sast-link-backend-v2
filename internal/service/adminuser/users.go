package adminuser

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
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
	// The keyword becomes three unindexable ILIKE predicates plus a matching COUNT(*)
	// over the table, so an unbounded one lets any reader make the database do
	// arbitrary work per request. Nothing here is rate limited. The bound is the widest
	// column it is matched against; anything longer cannot match a stored value.
	if !validate.WithinLength(input.Keyword, validate.MaxNameLength) {
		return nil, newError(ErrInvalidInput, fieldTooLongMessage("keyword"), nil)
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
		return nil, internalError(ctx, "list admin users", "查询用户列表失败", err)
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
		return nil, internalError(ctx, "get admin user detail", "查询用户详情失败", err)
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

	// Whether this edit is a role change is judged again inside the repository's
	// transaction, against the locked row. This comparison exists only to decide
	// whether to refuse the request outright: an administrator editing their own
	// account may change everything except the role, and that is a fact about the
	// caller rather than about the stored row, so a stale read cannot weaken it. The
	// last-admin guard and the session revocation are the repository's to arm.
	if validated.role != nil && *validated.role != current.Role && input.UserID == input.AdminUserID {
		selfErr := newError(ErrProtected, "不可修改自己的角色", nil)
		s.auditUpdate(ctx, input, false, errorCode(selfErr), nil)
		return nil, selfErr
	}

	entries, sessionsRevoked, err := s.Users.UpdateAdminUser(ctx, input.UserID, repository.AdminUserUpdate{
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
	}, s.now())
	if err != nil {
		mapped := s.mapWriteError(ctx, err)
		// No field was applied, so the entry records none. Logging the attempted set on a
		// rolled-back transaction would read as though the edit had landed.
		s.auditUpdate(ctx, input, false, errorCode(mapped), nil)
		return nil, mapped
	}
	s.deliverBlacklist(ctx, entries, s.now())
	// A role change that revoked sessions also clears the device set: the
	// user's every session was just cut, and the device list must not keep
	// showing logins that can no longer authenticate. Fail-open — the revoke
	// is durable in PostgreSQL and a leftover record expires on its own.
	//
	// The gate is the repository's authoritative flag, not len(entries): the
	// entries only collect still-live access tokens for blacklist delivery, so
	// a demotion of a user idle for over an hour revokes every refresh token
	// while returning zero entries.
	if sessionsRevoked && s.Devices != nil {
		if err := s.Devices.RemoveAllDevices(ctx, input.UserID); err != nil {
			slog.WarnContext(ctx, "remove all devices on admin update failed", "user_id", input.UserID, "error", err)
		}
	}
	s.auditUpdate(ctx, input, true, 0, validated.changed)
	// Report what the transaction actually revoked rather than what this layer
	// predicted: the repository judges the role change against the locked row, so its
	// answer is the only one that matches what happened. That authoritative flag is
	// sessionsRevoked, not len(entries) — the entries only collect still-live access
	// tokens for blacklist delivery, so a demotion of a user idle for over an hour
	// revokes every refresh token while returning zero entries, and reporting
	// "no sessions revoked" for that would contradict the device-set cleanup above.
	return &UpdateUserResult{ChangedFields: validated.changed, RevokedSessions: sessionsRevoked}, nil
}

// GetUsersByIDs returns the full records of the requested ids, in request
// order, with duplicates collapsed to their first occurrence.
//
// Order preservation is the point of the endpoint: the caller holds a list
// (mailing-batch targets, grading sheets) and reads the details back aligned
// with it. A missing id is silently absent rather than an error — SQL does not
// promise IN-list order and the caller diffs its own list, so an explicit
// per-id error here would only double the work.
func (s Service) GetUsersByIDs(ctx context.Context, input GetUsersByIDsInput) ([]UserDetail, error) {
	if s.Users == nil {
		return nil, newError(ErrInternal, "用户仓储未配置", nil)
	}
	ids, err := normalizeBatchIDs(input.IDs, maxBatchQueryIDs, "单次最多查询 100 个用户")
	if err != nil {
		return nil, err
	}
	rows, err := s.Users.FindByIDs(ctx, ids)
	if err != nil {
		return nil, internalError(ctx, "get admin users by ids", "批量查询用户失败", err)
	}
	byID := make(map[int64]model.User, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	details := make([]UserDetail, 0, len(ids))
	for _, id := range ids {
		row, ok := byID[id]
		if !ok {
			continue
		}
		details = append(details, userDetail(&row))
	}
	return details, nil
}

// UpdateUserRoles applies one role change to every id, independently, and
// reports each outcome.
//
// Deliberately not atomic: the caller needs to retry or alert on the failures
// (PRD-style batch semantics), and each item already runs its own transaction
// with its own guards — the self-demotion refusal, the last-admin check against
// the advisory lock, the closed-account state check, and the session revocation
// on an actual role change. Reusing UpdateUser per item means the batch cannot
// bypass a guard the single-user endpoint honors.
func (s Service) UpdateUserRoles(ctx context.Context, input UpdateUserRolesInput) (*UpdateUserRolesResult, error) {
	if s.Users == nil {
		return nil, newError(ErrInternal, "用户仓储未配置", nil)
	}
	role := model.UserRole(strings.TrimSpace(input.Role))
	if !validRole(role) {
		return nil, newError(ErrInvalidInput, "role 取值非法", nil)
	}
	ids, err := normalizeBatchIDs(input.IDs, maxBatchUpdateIDs, "单次最多更新 500 个用户")
	if err != nil {
		return nil, err
	}
	requestedRole := string(role)

	results := make([]RoleUpdateResult, 0, len(ids))
	for _, id := range ids {
		result := RoleUpdateResult{ID: id, Role: requestedRole}
		_, updateErr := s.UpdateUser(ctx, UpdateUserInput{
			UserID:        id,
			Role:          &requestedRole,
			Batch:         true,
			AdminUserID:   input.AdminUserID,
			ActorClientID: input.ActorClientID,
			ClientIP:      input.ClientIP,
			UserAgent:     input.UserAgent,
		})
		if updateErr == nil {
			result.Success = true
			results = append(results, result)
			continue
		}
		// A failure carries the reason and no role: the role was not applied, and
		// echoing it back would read as an outcome.
		result.Role = ""
		result.Reason = roleUpdateReason(updateErr)
		results = append(results, result)
	}
	return &UpdateUserRolesResult{Results: results}, nil
}

// roleUpdateReason turns a per-item update failure into the literal shown in
// the batch response. The messages mirror the single-user endpoint's HTTP
// mapping (mapUserServiceError), so a caller sees the same words whether one
// user or one hundred were submitted.
func roleUpdateReason(err error) string {
	var serviceErr *Error
	if !errors.As(err, &serviceErr) {
		return "服务器内部错误"
	}
	switch serviceErr.Kind {
	case KindInvalidInput, KindStateConflict, KindProtected:
		// The service's messages are literals naming the rule that was broken.
		return serviceErr.Message
	case KindNotFound:
		return "用户不存在"
	default:
		return "服务器内部错误"
	}
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
	// Closing the account cut every session; clear the device records so the
	// (deleted) user leaves no ghost logins behind. Fail-open — the user is
	// already gone.
	if s.Devices != nil {
		if err := s.Devices.RemoveAllDevices(ctx, input.UserID); err != nil {
			slog.WarnContext(ctx, "remove all devices on user delete failed", "user_id", input.UserID, "error", err)
		}
	}
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
			mapped = internalError(ctx, "restore admin user", "恢复用户失败", err)
		}
		s.auditTarget(ctx, input, actionRestoreUser, false, errorCode(mapped))
		return mapped
	}
	s.auditTarget(ctx, input, actionRestoreUser, true, 0)
	return nil
}

// loadTarget reads the account an edit is about to change.
func (s Service) loadTarget(ctx context.Context, userID int64) (*model.User, error) {
	user, err := s.Users.FindAuthUserByID(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrNotFound, "用户不存在", nil)
	}
	if err != nil {
		return nil, internalError(ctx, "load admin user target", "查询用户失败", err)
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
	// The account was closed between this request's read and its write. The row still
	// exists and the console is displaying it, so this is the same 422 the pre-flight
	// check reports rather than a 404 on a visible user.
	case errors.Is(err, repository.ErrStateConflict):
		return newError(ErrStateConflict, "用户已注销，请先恢复后再编辑", nil)
	case errors.Is(err, repository.ErrLastAdmin):
		return newError(ErrProtected, "系统中至少需要保留一名管理员", nil)
	}
	return s.mapUniqueViolation(ctx, err, "更新用户失败")
}

// mapDeleteError translates a repository failure from the soft-delete path.
func (s Service) mapDeleteError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return newError(ErrNotFound, "用户不存在", nil)
	case errors.Is(err, repository.ErrStateConflict):
		return newError(ErrStateConflict, "用户已注销", nil)
	case errors.Is(err, repository.ErrLastAdmin):
		return newError(ErrProtected, "系统中至少需要保留一名管理员", nil)
	}
	return internalError(ctx, "soft delete admin user", "注销用户失败", err)
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
	if input.Batch {
		// The batch role-update endpoint reuses this audit path per item; the marker
		// tells a mass promotion apart from an individual edit without a second action
		// name to maintain.
		detail["batch"] = true
	}
	s.audit(ctx, auditParams{
		AdminUserID:   input.AdminUserID,
		ActorClientID: input.ActorClientID,
		Action:        actionUpdateUser,
		TargetUserID:  input.UserID,
		Success:       success,
		ErrCode:       errCode,
		ClientIP:      input.ClientIP,
		UserAgent:     input.UserAgent,
		Detail:        detail,
	})
}

func (s Service) auditTarget(
	ctx context.Context,
	input TargetUserInput,
	action string,
	success bool,
	errCode int,
) {
	s.audit(ctx, auditParams{
		AdminUserID:   input.AdminUserID,
		ActorClientID: input.ActorClientID,
		Action:        action,
		TargetUserID:  input.UserID,
		Success:       success,
		ErrCode:       errCode,
		ClientIP:      input.ClientIP,
		UserAgent:     input.UserAgent,
	})
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
