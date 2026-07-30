package adminuser

import (
	"strings"
	"unicode/utf8"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
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
	maxLoginEmailLength  = 255
)

// Paging bounds. The contract documents a maximum of 100 for the user list and
// leaves the audit list open; an unbounded page size is a full-table read behind
// one request, so the same cap applies to both.
const (
	defaultUserPageSize  = 20
	defaultAuditPageSize = 50
	maxPageSize          = 100
)

// allowedEmailDomains mirrors session.isAllowedEmailDomain. The V001 trigger
// auto_set_email_type raises an exception for any other domain, so without this
// check an administrator's typo returns an unreadable 500 instead of a message
// naming the rule.
var allowedEmailDomains = []string{"@njupt.edu.cn", "@sast.fun"}

// userFieldOrder is the contract order used for the admin_user_update audit
// detail, so the log reads the same way regardless of map iteration.
var userFieldOrder = []string{
	"name", "phone_number", "qq_number", "student_id", "college", "major",
	"login_email", "role", "state", "email_type",
}

// validatedUpdate is the outcome of checking an UpdateUserInput.
type validatedUpdate struct {
	name        *string
	phoneNumber *string
	qqNumber    *string
	studentID   *string
	major       *string
	college     *model.College
	loginEmail  *string
	role        *model.UserRole
	state       *model.UserState
	emailType   *model.EmailType
	changed     []string
}

// validateUpdate checks every present field and returns the applied names in
// contract order.
//
// The "user" columns are NOT NULL, so a blank value is a rejection rather than a
// clear: an account with an empty name or student ID is not a valid record.
func validateUpdate(input UpdateUserInput) (validatedUpdate, error) {
	var result validatedUpdate
	present := make(map[string]bool, len(userFieldOrder))

	bounded := []struct {
		field  string
		value  *string
		limit  int
		target **string
	}{
		{"name", input.Name, maxNameLength, &result.name},
		{"phone_number", input.PhoneNumber, maxPhoneNumberLength, &result.phoneNumber},
		{"qq_number", input.QQNumber, maxQQNumberLength, &result.qqNumber},
		{"student_id", input.StudentID, maxStudentIDLength, &result.studentID},
		{"major", input.Major, maxMajorLength, &result.major},
	}
	for _, field := range bounded {
		if field.value == nil {
			continue
		}
		trimmed := strings.TrimSpace(*field.value)
		// major defaults to '' in V001 and is the one bounded column an administrator
		// may legitimately blank out; the rest identify the account.
		if trimmed == "" && field.field != "major" {
			return validatedUpdate{}, newError(ErrInvalidInput, fieldRequiredMessage(field.field), nil)
		}
		if utf8.RuneCountInString(trimmed) > field.limit {
			return validatedUpdate{}, newError(ErrInvalidInput, fieldTooLongMessage(field.field), nil)
		}
		if containsControlCharacter(trimmed) {
			return validatedUpdate{}, newError(ErrInvalidInput, fieldInvalidMessage(field.field), nil)
		}
		value := trimmed
		*field.target = &value
		present[field.field] = true
	}

	if input.College != nil {
		college := model.College(strings.TrimSpace(*input.College))
		if !college.Valid() {
			return validatedUpdate{}, newError(ErrInvalidInput, "college 取值非法", nil)
		}
		result.college = &college
		present["college"] = true
	}
	if input.Role != nil {
		role := model.UserRole(strings.TrimSpace(*input.Role))
		if !validRole(role) {
			return validatedUpdate{}, newError(ErrInvalidInput, "role 取值非法", nil)
		}
		result.role = &role
		present["role"] = true
	}
	if input.State != nil {
		state := model.UserState(strings.TrimSpace(*input.State))
		if !validState(state) {
			return validatedUpdate{}, newError(ErrInvalidInput, "state 取值非法", nil)
		}
		// Closing and reopening an account is DELETE's and restore's job. Those paths
		// revoke every token in the transaction that flips the flag; this one does not,
		// so accepting is_deleted here would leave a closed account holding live refresh
		// tokens. Refusing it keeps "a deleted account has no sessions" true by
		// construction rather than by remembering to duplicate the revocation.
		if state == model.UserStateDeleted {
			return validatedUpdate{}, newError(ErrStateConflict,
				"注销用户请使用 DELETE /admin/users/:id", nil)
		}
		result.state = &state
		present["state"] = true
	}

	loginEmail, err := validateLoginEmail(input.LoginEmail)
	if err != nil {
		return validatedUpdate{}, err
	}
	if loginEmail != nil {
		result.loginEmail = loginEmail
		present["login_email"] = true
	}

	emailType, err := validateEmailType(input.EmailType, loginEmail)
	if err != nil {
		return validatedUpdate{}, err
	}
	if emailType != nil {
		result.emailType = emailType
		present["email_type"] = true
	}

	result.changed = make([]string, 0, len(present))
	for _, field := range userFieldOrder {
		if present[field] {
			result.changed = append(result.changed, field)
		}
	}
	return result, nil
}

// validateLoginEmail normalizes and checks a replacement login email.
func validateLoginEmail(raw *string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	email := strings.ToLower(strings.TrimSpace(*raw))
	if email == "" {
		return nil, newError(ErrInvalidInput, "login_email 不能为空", nil)
	}
	if utf8.RuneCountInString(email) > maxLoginEmailLength {
		return nil, newError(ErrInvalidInput, "login_email 长度超出限制", nil)
	}
	if !validEmailFormat(email) {
		return nil, newError(ErrInvalidInput, "login_email 格式非法", nil)
	}
	if !allowedEmailDomain(email) {
		return nil, newError(ErrInvalidInput, "login_email 域名不允许", nil)
	}
	return &email, nil
}

// validateEmailType checks a submitted email_type against the domain that will be
// in effect after the write.
//
// The V001 trigger only recomputes email_type when login_email appears in the
// UPDATE column list, so a request carrying email_type alone can store a value
// that contradicts the address. The contract exposes the field, so it is accepted
// — but only when it agrees with the domain, which keeps the column's meaning
// intact. When login_email is absent there is nothing to compare against, so the
// field is refused rather than trusted; changing the address is how the type
// changes.
func validateEmailType(raw *string, loginEmail *string) (*model.EmailType, error) {
	if raw == nil {
		return nil, nil
	}
	emailType := model.EmailType(strings.TrimSpace(*raw))
	if !validEmailType(emailType) {
		return nil, newError(ErrInvalidInput, "email_type 取值非法", nil)
	}
	if loginEmail == nil {
		return nil, newError(ErrInvalidInput,
			"email_type 仅可随 login_email 一起修改，且必须与其域名一致", nil)
	}
	if emailType != emailTypeForDomain(*loginEmail) {
		return nil, newError(ErrInvalidInput, "email_type 与 login_email 域名不一致", nil)
	}
	return &emailType, nil
}

// emailTypeForDomain mirrors the V001 auto_set_email_type trigger.
func emailTypeForDomain(email string) model.EmailType {
	if strings.HasSuffix(email, "@sast.fun") {
		return model.EmailTypeSAST
	}
	return model.EmailTypeNJUpt
}

func allowedEmailDomain(email string) bool {
	for _, domain := range allowedEmailDomains {
		if strings.HasSuffix(email, domain) {
			return true
		}
	}
	return false
}

// validEmailFormat rejects control characters, address separators and display-name
// brackets, and requires exactly one @. Mirrors the session package's guard: the
// address reaches audit detail and PostgreSQL, so unprintable bytes and embedded
// separators are refused before the write.
func validEmailFormat(email string) bool {
	if strings.Count(email, "@") != 1 {
		return false
	}
	at := strings.IndexByte(email, '@')
	if at == 0 || at == len(email)-1 {
		return false
	}
	if strings.ContainsAny(email, " \t\r\n,;:<>()[]\\\"") {
		return false
	}
	if containsControlCharacter(email) {
		return false
	}
	// A domain needs a dot, and neither label may be empty.
	domain := email[at+1:]
	return strings.Contains(domain, ".") &&
		!strings.HasPrefix(domain, ".") && !strings.HasSuffix(domain, ".") &&
		!strings.Contains(domain, "..")
}

func containsControlCharacter(value string) bool {
	return strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func validRole(role model.UserRole) bool {
	switch role {
	case model.UserRoleFreshman, model.UserRoleMember, model.UserRoleLecturer, model.UserRoleAdmin:
		return true
	default:
		return false
	}
}

// validState accepts the closed set of state_enum values. is_deleted is a valid
// enum member and is filtered separately by validateUpdate, which rejects it with
// a message pointing at the right endpoint.
func validState(state model.UserState) bool {
	switch state {
	case model.UserStateNJUPTer, model.UserStateOnSAST,
		model.UserStateRetiredSAST, model.UserStateDeleted:
		return true
	default:
		return false
	}
}

func validEmailType(emailType model.EmailType) bool {
	switch emailType {
	case model.EmailTypeSAST, model.EmailTypeNJUpt:
		return true
	default:
		return false
	}
}

// The messages below are built from a fixed field name, never from a submitted
// value, so nothing the caller sends is reflected back.
func fieldRequiredMessage(field string) string { return field + " 不能为空" }
func fieldTooLongMessage(field string) string  { return field + " 长度超出限制" }
func fieldInvalidMessage(field string) string  { return field + " 含非法字符" }

// normalizePaging clamps a requested page window. A non-positive page or size is
// the handler's signal that the caller omitted it; an out-of-range size is capped
// rather than rejected, matching the contract's documented maximum.
func normalizePaging(page, pageSize, defaultSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = defaultSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return page, pageSize
}
