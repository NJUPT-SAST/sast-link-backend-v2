package adminuser

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/shared"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// ListUsers returns a filtered page of accounts; reads are not audited, and
// soft-deleted accounts are included so the console can restore them.
func (s Service) ListUsers(ctx context.Context, input ListUsersInput) (*ListUsersResult, error) {
	if s.Users == nil {
		return nil, newError(ErrInternal, "用户仓储未配置", nil)
	}
	// An unbounded keyword becomes unindexable ILIKE predicates over the whole
	// table, so it is capped at the widest matched column.
	if !validate.WithinLength(input.Keyword, validate.MaxNameLength) {
		return nil, newError(ErrInvalidInput, fieldTooLongMessage("keyword"), nil)
	}
	page, pageSize := normalizePaging(input.Page, input.PageSize, defaultUserPageSize)
	filter := repository.AdminUserFilter{
		StudentID:          input.StudentID,
		Keyword:            input.Keyword,
		IncludePhoneColumn: input.IncludePhoneColumn,
		NeedsCompletion:    input.NeedsCompletion,
		Limit:              pageSize,
		Offset:             (page - 1) * pageSize,
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

// UpdateUser applies a partial administrative edit with two extra guards: an
// administrator cannot change their own role (self-demotion is unrecoverable), and
// the last active administrator cannot be demoted — a count over other rows, so the
// repository serializes it inside its transaction to stop concurrent demotions.
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
	// A closed account must be restored before editing; checking here turns the SQL
	// exclusion into a 422 explaining the order.
	if current.State == model.UserStateDeleted {
		closedErr := newError(ErrStateConflict, "用户已注销，请先恢复后再编辑", nil)
		s.auditUpdate(ctx, input, false, errorCode(closedErr), nil)
		return nil, closedErr
	}

	// The bound address must also differ from the login email already on the row:
	// validateUpdate only compared against a login_email being replaced in this same
	// request. The V005 trigger would reject the pair anyway, but naming the field
	// in a 400 reads better than a collision at insert time.
	if validated.personalEmail != nil && strings.EqualFold(*validated.personalEmail, current.LoginEmail) {
		equalErr := newError(ErrInvalidInput, "personal_email 不能与 login_email 相同", nil)
		s.auditUpdate(ctx, input, false, errorCode(equalErr), nil)
		return nil, equalErr
	}

	// The role-change test here exists only to refuse self-demotion outright; the
	// repository re-judges the change against the locked row and arms the last-admin
	// guard and the session revocation itself.
	if validated.role != nil && *validated.role != current.Role && input.UserID == input.AdminUserID {
		selfErr := newError(ErrProtected, "不可修改自己的角色", nil)
		s.auditUpdate(ctx, input, false, errorCode(selfErr), nil)
		return nil, selfErr
	}

	// The manager boundary: a manager may run every member-management write —
	// promote to manager or lecturer included, self-replication is the point of
	// the role — but never touch an admin's account and never grant the admin
	// role. Checked against the freshly loaded row, and the batch endpoint routes
	// through here too, so it cannot bypass the boundary either.
	if !callerIsAdmin(input.AdminRole) {
		if current.Role == model.UserRoleAdmin {
			adminTargetErr := newError(ErrProtected, "无权操作管理员账号", nil)
			s.auditUpdate(ctx, input, false, errorCode(adminTargetErr), nil)
			return nil, adminTargetErr
		}
		if validated.role != nil && *validated.role == model.UserRoleAdmin {
			grantErr := newError(ErrProtected, "不可授予 admin 角色", nil)
			s.auditUpdate(ctx, input, false, errorCode(grantErr), nil)
			return nil, grantErr
		}
	}

	entries, sessionsRevoked, err := s.Users.UpdateAdminUser(ctx, input.UserID, repository.AdminUserUpdate{
		CallerUserID:  input.AdminUserID,
		Name:          validated.name,
		PhoneNumber:   validated.phoneNumber,
		QQNumber:      validated.qqNumber,
		StudentID:     validated.studentID,
		Major:         validated.major,
		College:       validated.college,
		LoginEmail:    validated.loginEmail,
		Role:          validated.role,
		State:         validated.state,
		StateAuto:     validated.stateAuto,
		EmailType:     validated.emailType,
		PersonalEmail: validated.personalEmail,
		Department:    validated.department,
		// A role change invalidates sessions: a demoted account's live refresh tokens
		// must not keep minting tokens for a session meant to end.
	}, model.UserRole(input.AdminRole), s.now())
	if err != nil {
		mapped := s.mapWriteError(ctx, err)
		// The write failed, so the audit records no changed fields; a rolled-back
		// entry reading as landed would be a lie.
		s.auditUpdate(ctx, input, false, errorCode(mapped), nil)
		return nil, mapped
	}
	shared.DeliverBlacklist(ctx, s.Blacklist, entries, s.now())
	// A role change that revoked sessions also clears the device set, so it stops
	// showing logins that can no longer authenticate; fail-open, since the revoke is
	// durable and a leftover record expires on its own. The gate is the repository's
	// authoritative flag, not len(entries), which only counts still-live access
	// tokens.
	if sessionsRevoked && s.Devices != nil {
		if err := s.Devices.RemoveAllDevices(ctx, input.UserID); err != nil {
			slog.WarnContext(ctx, "remove all devices on admin update failed", "user_id", input.UserID, "error", err)
		}
	}
	s.auditUpdate(ctx, input, true, 0, validated.changed)
	// Report the repository's authoritative flag, not this layer's prediction:
	// sessionsRevoked, not len(entries).
	return &UpdateUserResult{ChangedFields: validated.changed, RevokedSessions: sessionsRevoked}, nil
}

// GetUsersByIDs returns the full records of the requested ids, in request order,
// with duplicates collapsed to their first occurrence; a missing id is silently
// absent rather than an error.
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

// BatchUpdateUsers applies the requested role and/or department change to every
// id, independently, and reports each outcome. Deliberately not atomic: each
// item runs its own UpdateUser transaction with its own guards, so the batch
// cannot bypass a guard the single-user endpoint honors.
func (s Service) BatchUpdateUsers(ctx context.Context, input BatchUpdateUsersInput) (*BatchUpdateUsersResult, error) {
	if s.Users == nil {
		return nil, newError(ErrInternal, "用户仓储未配置", nil)
	}
	// TrimSpace-then-empty is the deliberate reading of a blank role: whitespace
	// carries no change anyone could apply, so it counts as "not requested"
	// rather than "requested an invalid value" — matching how a blank department
	// reads as the clear, not an enum violation.
	role := model.UserRole(strings.TrimSpace(input.Role))
	roleRequested := role != ""
	if roleRequested && !validRole(role) {
		return nil, newError(ErrInvalidInput, "role 取值非法", nil)
	}
	// A body carrying neither change is refused before the loop, so the endpoint
	// stays a write and not a no-op probe.
	if !roleRequested && input.Department == nil {
		return nil, newError(ErrInvalidInput, "没有需要更新的字段", nil)
	}
	// The department enum is checked request-wide so an unknown value is a 400 on
	// the whole batch, mirroring the role check above; UpdateUser re-validates
	// per item regardless, so the two checks cannot drift apart in outcome.
	var requestedDepartment *string
	if input.Department != nil {
		department := model.Department(strings.TrimSpace(*input.Department))
		if department != "" && !department.Valid() {
			return nil, newError(ErrInvalidInput, "department 取值非法", nil)
		}
		applied := string(department)
		requestedDepartment = &applied
	}
	ids, err := normalizeBatchIDs(input.IDs, maxBatchUpdateIDs, "单次最多更新 500 个用户")
	if err != nil {
		return nil, err
	}
	requestedRole := string(role)

	results := make([]BatchUpdateResult, 0, len(ids))
	for _, id := range ids {
		result := BatchUpdateResult{ID: id, Department: requestedDepartment}
		if roleRequested {
			result.Role = requestedRole
		}
		update := UpdateUserInput{
			UserID:        id,
			Batch:         true,
			AdminUserID:   input.AdminUserID,
			AdminRole:     input.AdminRole,
			ActorClientID: input.ActorClientID,
			ClientIP:      input.ClientIP,
			UserAgent:     input.UserAgent,
		}
		if roleRequested {
			update.Role = &requestedRole
		}
		if input.Department != nil {
			update.Department = requestedDepartment
		}
		_, updateErr := s.UpdateUser(ctx, update)
		if updateErr == nil {
			result.Success = true
			results = append(results, result)
			continue
		}
		// A failure carries the reason and no echo of the requested changes, since
		// neither was applied.
		result.Role = ""
		result.Department = nil
		result.Reason = batchUpdateReason(updateErr)
		results = append(results, result)
	}
	return &BatchUpdateUsersResult{Results: results}, nil
}

// batchUpdateReason turns a per-item update failure into the literal shown in
// the batch response. The messages mirror the single-user endpoint's HTTP
// mapping (mapUserServiceError), so a caller sees the same words whether one
// user or one hundred were submitted.
func batchUpdateReason(err error) string {
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
	// Closing your own account is refused, like self-demotion: it locks you out of
	// the very endpoint that would reopen it.
	if input.UserID == input.AdminUserID {
		err := newError(ErrProtected, "不可注销自己的账号", nil)
		s.auditTarget(ctx, input, actionDeleteUser, false, errorCode(err))
		return err
	}
	// A manager cannot close an administrator's account; the row is read before
	// the write so the refusal is judged against the live role.
	if targetErr := s.refuseManagerOnAdminTarget(ctx, input.AdminRole, input.UserID, actionDeleteUser, input); targetErr != nil {
		return targetErr
	}
	entries, err := s.Users.SoftDeleteAndRevokeSessions(ctx, input.UserID, model.UserRole(input.AdminRole), s.now())
	if err != nil {
		mapped := s.mapDeleteError(ctx, err)
		s.auditTarget(ctx, input, actionDeleteUser, false, errorCode(mapped))
		return mapped
	}
	shared.DeliverBlacklist(ctx, s.Blacklist, entries, s.now())
	// Clear the device records so the closed account leaves no ghost logins behind;
	// fail-open — the user is already gone.
	if s.Devices != nil {
		if err := s.Devices.RemoveAllDevices(ctx, input.UserID); err != nil {
			slog.WarnContext(ctx, "remove all devices on user delete failed", "user_id", input.UserID, "error", err)
		}
	}
	s.auditTarget(ctx, input, actionDeleteUser, true, 0)
	return nil
}

// RestoreUser reopens a closed account with the derived state (internal/
// validate), clearing any manual pin — the DELETE that closed the account
// already overwrote the pinned value, so the restore cannot preserve it.
func (s Service) RestoreUser(ctx context.Context, input TargetUserInput) error {
	if s.Users == nil {
		return newError(ErrInternal, "用户仓储未配置", nil)
	}
	if input.UserID <= 0 {
		return newError(ErrNotFound, "用户不存在", nil)
	}
	// A manager cannot reopen an administrator's account either: restoring is a
	// write on the account, and the role survives the close (DELETE flips state,
	// not role).
	if targetErr := s.refuseManagerOnAdminTarget(ctx, input.AdminRole, input.UserID, actionRestoreUser, input); targetErr != nil {
		return targetErr
	}
	err := s.Users.RestoreUser(ctx, input.UserID, model.UserRole(input.AdminRole), s.now())
	if err != nil {
		var mapped error
		switch {
		case errors.Is(err, repository.ErrNotFound):
			mapped = newError(ErrNotFound, "用户不存在", nil)
		case errors.Is(err, repository.ErrStateConflict):
			mapped = newError(ErrStateConflict, "用户未被注销，无需恢复", nil)
		case errors.Is(err, repository.ErrAdminTarget):
			mapped = newError(ErrProtected, "无权操作管理员账号", nil)
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

// callerIsAdmin reports whether the acting principal holds the admin role. Only
// the literal unlocks the admin-only writes; anything else — empty, a manager,
// a value a future role adds — stays on the restricted side of the boundary.
func callerIsAdmin(role string) bool {
	return role == string(model.UserRoleAdmin)
}

// refuseManagerOnAdminTarget rejects a non-admin caller's action against an
// administrator's account. Used by the delete and restore paths, whose write
// goes straight to the repository; the role is read from the live row (which a
// close does not change) so a deleted admin cannot be reopened behind the
// boundary either.
func (s Service) refuseManagerOnAdminTarget(
	ctx context.Context,
	callerRole string,
	userID int64,
	action string,
	input TargetUserInput,
) error {
	if callerIsAdmin(callerRole) {
		return nil
	}
	target, err := s.loadTarget(ctx, userID)
	if err != nil {
		// Missing or unreadable targets keep their existing mapping below: the
		// repository reports not-found, and an unreadable row is an internal error.
		// Refusing here with a different code would only mask it.
		return nil
	}
	if target.Role != model.UserRoleAdmin {
		return nil
	}
	refused := newError(ErrProtected, "无权操作管理员账号", nil)
	s.auditTarget(ctx, input, action, false, errorCode(refused))
	return refused
}

// mapWriteError translates a repository failure from the update path.
func (s Service) mapWriteError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return newError(ErrNotFound, "用户不存在", nil)
	// The account was closed between read and write; the row still exists, so it is
	// the same 422 the pre-flight check reports rather than a 404 on a visible user.
	case errors.Is(err, repository.ErrStateConflict):
		return newError(ErrStateConflict, "用户已注销，请先恢复后再编辑", nil)
	case errors.Is(err, repository.ErrLastAdmin):
		return newError(ErrProtected, "系统中至少需要保留一名管理员", nil)
	case errors.Is(err, repository.ErrSelfRoleChange):
		return newError(ErrProtected, "不可修改自己的角色", nil)
	case errors.Is(err, repository.ErrAdminTarget):
		return newError(ErrProtected, "无权操作管理员账号", nil)
	case errors.Is(err, repository.ErrAdminGrant):
		return newError(ErrProtected, "不可授予 admin 角色", nil)
	case errors.Is(err, repository.ErrIdentityLimitExceeded):
		return newError(ErrIdentityLimitReached, "第三方邮箱绑定数量已达上限", nil)
	// state_auto cannot derive from an unreadable student ID. That is a field the
	// administrator can fix (re-pin with an explicit state), so it reads as a 400
	// naming the cause rather than an opaque 500.
	case errors.Is(err, repository.ErrInvalidArgument):
		return newError(ErrInvalidInput, "学号无法解析入学年份，请改用显式 state 钉住", nil)
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
	case errors.Is(err, repository.ErrAdminTarget):
		return newError(ErrProtected, "无权操作管理员账号", nil)
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
	// Field names only, never their values, which would outlive the request readable
	// by every administrator.
	detail := map[string]any{}
	if len(changed) > 0 {
		detail["changed_fields"] = changed
	}
	if input.Batch {
		// Marks a batch role-update edit, so the log reads a mass promotion apart
		// from an individual edit.
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
