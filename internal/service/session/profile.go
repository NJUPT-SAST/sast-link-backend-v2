package session

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/shared"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// profileFieldOrder is the contract order used for the update_profile audit
// detail, so the log reads the same way regardless of map iteration.
//
// student_id has no entry: the self-service edit accepted it once, guarded only
// by the case-sensitive unique constraint, so a user could squat a case variant
// of another account's ID. Changing a student ID is an administrator's
// correction, not a self-service edit — PUT /admin/users/:id carries the
// folded occupancy pre-check and the NJUPT-prefix collision guard.
var profileFieldOrder = []string{
	"name", "phone_number", "qq_number", "college", "major",
	"nickname", "department", "intro", "email", "blog_url", "github_url",
}

// UpdateProfile applies a partial self-service edit to the caller's own record.
// Only the fields PRD §4.9 assigns to the user are accepted: login_email, role,
// state, email_type and student_id have no entry in the input, so no request can
// reach them — the strict JSON decoder answers an unknown student_id key with
// 400 rather than silently ignoring it. department additionally carries a role
// gate (manager/admin only — see departmentSelfEditRoles). Every present field
// is validated before the write, so a partial failure cannot leave the user
// table updated and profile untouched.
func (s Service) UpdateProfile(ctx context.Context, input UpdateProfileInput) (*UpdateProfileResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	update, changed, err := buildProfileUpdate(input)
	if err != nil {
		return nil, err
	}
	if len(changed) == 0 {
		return nil, newError(ErrInvalidInput, "没有需要更新的字段", nil)
	}

	user, err := s.Users.UpdateProfile(ctx, input.UserID, update)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	if err != nil {
		// No self-service field is unique, so a unique violation here is unmapped
		// by definition (student_id edits left with the admin surface); it logs and
		// reads as a conflict rather than a 500 naming no field.
		if constraint := duplicateConstraint(err); constraint != "" {
			slog.ErrorContext(ctx, "unmapped unique violation on update profile", "constraint", constraint)
			return nil, newError(ErrConflict, "资料与现有账号冲突", err)
		}
		return nil, newError(ErrInternal, "更新用户资料失败", err)
	}

	if auditErr := s.audit(ctx, &input.UserID, "update_profile", "user", resourceID(input.UserID), shared.NullableString(shared.ActorClientID(input.ActorClientID, s.InternalClientID)), true, 0,
		input.ClientIP, input.UserAgent, map[string]any{"changed_fields": changed}); auditErr != nil {
		slog.Error("audit update profile", "user_id", input.UserID, "error", auditErr)
	}
	return &UpdateProfileResult{Profile: profileDTO(user), ChangedFields: changed}, nil
}

// buildProfileUpdate validates the present fields and returns the repository
// update plus the applied field names in contract order.
func buildProfileUpdate(input UpdateProfileInput) (repository.ProfileUpdate, []string, error) {
	update := repository.ProfileUpdate{}
	present := make(map[string]bool, len(profileFieldOrder))

	// "user" columns are NOT NULL, so a blank value is a rejection rather than a
	// clear: an account with an empty name or student ID is not a valid record.
	required := []struct {
		field string
		value *string
		limit int
		into  **string
	}{
		{"name", input.Name, validate.MaxNameLength, &update.Name},
		{"phone_number", input.PhoneNumber, validate.MaxPhoneNumberLength, &update.PhoneNumber},
		{"qq_number", input.QQNumber, validate.MaxQQNumberLength, &update.QQNumber},
		{"major", input.Major, validate.MaxMajorLength, &update.Major},
	}
	for _, entry := range required {
		if entry.value == nil {
			continue
		}
		trimmed := strings.TrimSpace(*entry.value)
		if trimmed == "" {
			return update, nil, newError(ErrInvalidInput, entry.field+" 不能为空", nil)
		}
		if utf8.RuneCountInString(trimmed) > entry.limit {
			return update, nil, newError(ErrInvalidInput, entry.field+" 超出长度限制", nil)
		}
		if validate.HasControlCharacter(trimmed) {
			return update, nil, newError(ErrInvalidInput, entry.field+" 含非法字符", nil)
		}
		value := trimmed
		*entry.into = &value
		present[entry.field] = true
	}

	// The character rule is name-only: the product accepts Han + interpunct
	// (frontend realNameSchema), and a name the frontend refuses must not be
	// stored through an API that bypasses it — otherwise the account lands in
	// the completion loop the rule exists to break. The shape checks above
	// already reject blank/over-long/control characters; this rejects any
	// other character the whitelist excludes.
	if input.Name != nil && validate.IsInvalidName(*input.Name) {
		return update, nil, newError(ErrInvalidInput, "name 仅限中文与间隔号（·）", nil)
	}

	if input.College != nil {
		college := model.College(strings.TrimSpace(*input.College))
		if !college.Valid() {
			return update, nil, newError(ErrInvalidInput, "学院不在枚举范围内", nil)
		}
		update.College = &college
		present["college"] = true
	}

	// profile columns are nullable display fields, so an explicit empty string is
	// a legitimate "clear this" and passes through as NULL.
	optional := []struct {
		field string
		value *string
		limit int
		into  **string
	}{
		{"nickname", input.Nickname, validate.MaxNicknameLength, &update.Nickname},
		{"intro", input.Intro, validate.MaxIntroLength, &update.Intro},
		{"email", input.Email, validate.MaxDisplayEmailLen, &update.Email},
		{"blog_url", input.BlogURL, validate.MaxURLLength, &update.BlogURL},
		{"github_url", input.GitHubURL, validate.MaxURLLength, &update.GitHubURL},
	}
	for _, entry := range optional {
		if entry.value == nil {
			continue
		}
		trimmed := strings.TrimSpace(*entry.value)
		if utf8.RuneCountInString(trimmed) > entry.limit {
			return update, nil, newError(ErrInvalidInput, entry.field+" 超出长度限制", nil)
		}
		if validate.HasControlCharacter(trimmed) {
			return update, nil, newError(ErrInvalidInput, entry.field+" 含非法字符", nil)
		}
		value := trimmed
		*entry.into = &value
		present[entry.field] = true
	}

	// The display email is shown on a public card, not used for login or delivery,
	// but it still travels through logs and the card response, so it gets the same
	// control-character and shape guard as every other address in this service.
	if update.Email != nil && *update.Email != "" {
		if !validate.EmailFormat(normalizeIdentifier(*update.Email)) {
			return update, nil, newError(ErrInvalidInput, "展示邮箱格式不正确", nil)
		}
	}
	for _, link := range []struct {
		field string
		value *string
	}{{"blog_url", update.BlogURL}, {"github_url", update.GitHubURL}} {
		if link.value == nil || *link.value == "" {
			continue
		}
		if !validHTTPURL(*link.value) {
			return update, nil, newError(ErrInvalidInput, link.field+" 必须是 http/https 链接", nil)
		}
	}

	if input.Department != nil {
		// department is an organizational field, not a display one: it feeds
		// the console's department filters and downstream membership systems, so
		// the self-service edit accepts it only from the roles the admin surface
		// trusts with the same write (manager/admin). Any other role submitting
		// the key is rejected — the same posture as a permission field the path
		// does not expose — rather than silently dropping it: a caller must not
		// believe an edit landed when it did not.
		if !departmentSelfEditAllowed(input.Role) {
			return update, nil, newError(ErrInvalidInput, "部门仅限管理员修改", nil)
		}
		department := model.Department(strings.TrimSpace(*input.Department))
		// An empty department clears the column; any other value must be a real
		// department_enum member, or PostgreSQL rejects it as a 500 rather than a
		// field error.
		if department != "" && !department.Valid() {
			return update, nil, newError(ErrInvalidInput, "部门不在枚举范围内", nil)
		}
		update.Department = &department
		present["department"] = true
	}

	changed := make([]string, 0, len(present))
	for _, field := range profileFieldOrder {
		if present[field] {
			changed = append(changed, field)
		}
	}
	return update, changed, nil
}

func resourceID(userID int64) *string {
	value := strconv.FormatInt(userID, 10)
	return &value
}

// departmentSelfEditRoles is the role set allowed to write its own department
// through PUT /user/profile — the same write roles the admin surface grants
// (manager/admin); lecturer stays a directory reader. Membership is decided on
// the live database role, so an unknown or blank role is a refusal, not a pass.
var departmentSelfEditRoles = map[model.UserRole]bool{
	model.UserRoleManager: true,
	model.UserRoleAdmin:   true,
}

func departmentSelfEditAllowed(role string) bool {
	return departmentSelfEditRoles[model.UserRole(role)]
}
