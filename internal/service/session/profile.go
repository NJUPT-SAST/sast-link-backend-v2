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
)

// Column widths from V001. Rejecting an over-long value here turns a PostgreSQL
// "value too long for type character varying(n)" — which surfaces as an opaque
// 500 — into a 40000 naming the field.
const (
	maxNameLength        = 255
	maxPhoneNumberLength = 20
	maxQQNumberLength    = 20
	maxStudentIDLength   = 50
	maxMajorLength       = 50
	maxNicknameLength    = 255
	maxIntroLength       = 255
	maxDisplayEmailLen   = 255
	maxURLLength         = 512
)

// profileFieldOrder is the contract order used for the update_profile audit
// detail, so the log reads the same way regardless of map iteration.
var profileFieldOrder = []string{
	"name", "phone_number", "qq_number", "student_id", "college", "major",
	"nickname", "department", "intro", "email", "blog_url", "github_url",
}

// UpdateProfile applies a partial self-service edit to the caller's own record.
//
// Only the fields PRD §4.9 assigns to the user are accepted; login_email, role,
// state and email_type have no entry in UpdateProfileInput at all, so no request
// shape can reach them. Every present field is validated before the write, since
// a partial failure would leave the user table updated and profile untouched.
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
		// student_id is unique, so a concurrent registration or edit can collide.
		// Dispatch on the constraint name rather than reporting a generic conflict:
		// the user needs to know which field to change.
		switch constraint := duplicateConstraint(err); constraint {
		case userStudentIDConstraint:
			return nil, newError(ErrStudentIDOccupied, "学号已被占用", err)
		case "":
		default:
			slog.ErrorContext(ctx, "unmapped unique violation on update profile", "constraint", constraint)
			return nil, newError(ErrConflict, "资料与现有账号冲突", err)
		}
		return nil, newError(ErrInternal, "更新用户资料失败", err)
	}

	if auditErr := s.audit(ctx, &input.UserID, "update_profile", "user", resourceID(input.UserID), true, 0,
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
		{"name", input.Name, maxNameLength, &update.Name},
		{"phone_number", input.PhoneNumber, maxPhoneNumberLength, &update.PhoneNumber},
		{"qq_number", input.QQNumber, maxQQNumberLength, &update.QQNumber},
		{"student_id", input.StudentID, maxStudentIDLength, &update.StudentID},
		{"major", input.Major, maxMajorLength, &update.Major},
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
		value := trimmed
		*entry.into = &value
		present[entry.field] = true
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
		{"nickname", input.Nickname, maxNicknameLength, &update.Nickname},
		{"intro", input.Intro, maxIntroLength, &update.Intro},
		{"email", input.Email, maxDisplayEmailLen, &update.Email},
		{"blog_url", input.BlogURL, maxURLLength, &update.BlogURL},
		{"github_url", input.GitHubURL, maxURLLength, &update.GitHubURL},
	}
	for _, entry := range optional {
		if entry.value == nil {
			continue
		}
		trimmed := strings.TrimSpace(*entry.value)
		if utf8.RuneCountInString(trimmed) > entry.limit {
			return update, nil, newError(ErrInvalidInput, entry.field+" 超出长度限制", nil)
		}
		value := trimmed
		*entry.into = &value
		present[entry.field] = true
	}

	// The display email is shown on a public card, not used for login or delivery,
	// but it still travels through logs and the card response, so it gets the same
	// control-character and shape guard as every other address in this service.
	if update.Email != nil && *update.Email != "" {
		if !validEmailFormat(normalizeIdentifier(*update.Email)) {
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
		department := model.Department(strings.TrimSpace(*input.Department))
		// An empty department clears the column; any other value must be a real
		// department_enum member or PostgreSQL would reject it as an invalid enum
		// input, which reaches the client as a 500 rather than a field error.
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
