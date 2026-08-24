package adminuser

import (
	"strings"
	"unicode/utf8"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// Paging bounds. The contract documents a maximum of 100 for the user list and
// leaves the audit list open; an unbounded page size is a full-table read behind
// one request, so the same cap applies to both.
const (
	defaultUserPageSize  = 20
	defaultAuditPageSize = 50
)

// Batch caps. The query cap is the contract's documented maximum (100); the
// update cap is higher because its documented use is a recruitment promotion of
// hundreds of accounts, and each item is an independent single-row transaction.
// Both are far below what one request could plausibly need, so a caller that
// hits them is misusing the endpoint, not paging.
const (
	maxBatchQueryIDs  = 100
	maxBatchUpdateIDs = 500
)

// normalizeBatchIDs validates a batch id list and collapses duplicates, keeping
// first-occurrence order.
//
// The cap is checked against the submitted length before deduplication, so the
// response cannot be steered by padding — sending 200 ids, 150 of them
// duplicates, is still 200 ids. Messages are literals at the call site, so each
// endpoint names its own bound.
func normalizeBatchIDs(ids []int64, limit int, tooManyMessage string) ([]int64, error) {
	if len(ids) == 0 {
		return nil, newError(ErrInvalidInput, "ids 不能为空", nil)
	}
	if len(ids) > limit {
		return nil, newError(ErrInvalidInput, tooManyMessage, nil)
	}
	seen := make(map[int64]struct{}, len(ids))
	normalized := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			return nil, newError(ErrInvalidInput, "用户 id 必须为正整数", nil)
		}
		if _, duplicated := seen[id]; duplicated {
			continue
		}
		seen[id] = struct{}{}
		normalized = append(normalized, id)
	}
	return normalized, nil
}

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
		{"name", input.Name, validate.MaxNameLength, &result.name},
		{"phone_number", input.PhoneNumber, validate.MaxPhoneNumberLength, &result.phoneNumber},
		{"qq_number", input.QQNumber, validate.MaxQQNumberLength, &result.qqNumber},
		{"student_id", input.StudentID, validate.MaxStudentIDLength, &result.studentID},
		{"major", input.Major, validate.MaxMajorLength, &result.major},
	}
	for _, field := range bounded {
		if field.value == nil {
			continue
		}
		// major defaults to '' in V001 and is the one bounded column an administrator
		// may legitimately blank out; the rest identify the account. That is exactly the
		// Required/Optional split, so the two helpers carry it rather than a field-name
		// comparison inside a shared branch.
		var (
			trimmed string
			refused *validate.FieldError
		)
		if field.field == "major" {
			trimmed, refused = validate.OptionalField(field.field, *field.value, field.limit)
		} else {
			trimmed, refused = validate.RequiredField(field.field, *field.value, field.limit)
		}
		if refused != nil {
			return validatedUpdate{}, fieldError(refused)
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
	if utf8.RuneCountInString(email) > validate.MaxLoginEmailLength {
		return nil, newError(ErrInvalidInput, "login_email 长度超出限制", nil)
	}
	if !validate.EmailFormat(email) {
		return nil, newError(ErrInvalidInput, "login_email 格式非法", nil)
	}
	if !validate.IsLoginEmailDomain(email) {
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

// fieldError maps a validate.FieldError onto this service's invalid-input error.
//
// The rule lives in internal/validate because the alumni account-request flow
// applies the same one, but the wording stays here: that flow is anonymous and
// must not answer with copy written for the console. An unrecognized reason
// falls through to the invalid-character message rather than being dropped,
// since returning nil would let a refused value continue as if it had passed.
func fieldError(refused *validate.FieldError) error {
	switch refused.Reason {
	case validate.ReasonRequired:
		return newError(ErrInvalidInput, fieldRequiredMessage(refused.Field), nil)
	case validate.ReasonTooLong:
		return newError(ErrInvalidInput, fieldTooLongMessage(refused.Field), nil)
	default:
		return newError(ErrInvalidInput, fieldInvalidMessage(refused.Field), nil)
	}
}

// validatedCreate holds the normalized CreateUserInput. Optional fields are
// resolved to their defaults; there are no nil-or-unchanged semantics.
type validatedCreate struct {
	name          string
	phoneNumber   string
	qqNumber      string
	studentID     string
	major         string
	college       model.College
	loginEmail    string
	role          model.UserRole
	state         model.UserState
	personalEmail *string
}

// validateCreate checks a full account provision. name, phone_number, qq_number,
// student_id and login_email are required; major may stay empty. role defaults
// to member and state to retired_sast, the usual case for graduated members
// whose school or SAST email is no longer reachable.
func validateCreate(input CreateUserInput) (validatedCreate, error) {
	var result validatedCreate

	required := []struct {
		field  string
		value  string
		limit  int
		target *string
	}{
		{"name", input.Name, validate.MaxNameLength, &result.name},
		{"phone_number", input.PhoneNumber, validate.MaxPhoneNumberLength, &result.phoneNumber},
		{"qq_number", input.QQNumber, validate.MaxQQNumberLength, &result.qqNumber},
		{"student_id", input.StudentID, validate.MaxStudentIDLength, &result.studentID},
	}
	for _, field := range required {
		value, refused := validate.RequiredField(field.field, field.value, field.limit)
		if refused != nil {
			return validatedCreate{}, fieldError(refused)
		}
		*field.target = value
	}

	major := ""
	if input.Major != nil {
		// major is the one provisioning field the console may leave empty, so it goes
		// through OptionalField. The alumni ticket flow requires it instead, because a
		// blank major is what V010's generated column flags as incomplete.
		validated, refused := validate.OptionalField("major", *input.Major, validate.MaxMajorLength)
		if refused != nil {
			return validatedCreate{}, fieldError(refused)
		}
		major = validated
	}
	result.major = major

	college := model.CollegeOther
	if input.College != nil {
		college = model.College(strings.TrimSpace(*input.College))
		if !college.Valid() {
			return validatedCreate{}, newError(ErrInvalidInput, "college 取值非法", nil)
		}
	}
	result.college = college

	loginEmail, err := validateLoginEmail(&input.LoginEmail)
	if err != nil {
		// validateLoginEmail answers nil for a nil input; the required strings have
		// no such presence, so re-state the empty case with the field's own message.
		return validatedCreate{}, err
	}
	result.loginEmail = *loginEmail

	if input.PersonalEmail != nil {
		email := strings.ToLower(strings.TrimSpace(*input.PersonalEmail))
		if email == "" {
			return validatedCreate{}, newError(ErrInvalidInput, "personal_email 不能为空", nil)
		}
		if utf8.RuneCountInString(email) > validate.MaxLoginEmailLength {
			return validatedCreate{}, newError(ErrInvalidInput, "personal_email 长度超出限制", nil)
		}
		if !validate.EmailFormat(email) {
			return validatedCreate{}, newError(ErrInvalidInput, "personal_email 格式非法", nil)
		}
		if email == result.loginEmail {
			// Reject before the identity insert so the caller gets a clear input error
			// rather than a DB constraint. Both emails are lowercased, so compare exactly.
			return validatedCreate{}, newError(ErrInvalidInput, "personal_email 不能与 login_email 相同", nil)
		}
		result.personalEmail = &email
	}

	role := model.UserRoleMember
	if input.Role != nil {
		role = model.UserRole(strings.TrimSpace(*input.Role))
		if !validRole(role) {
			return validatedCreate{}, newError(ErrInvalidInput, "role 取值非法", nil)
		}
	}
	result.role = role

	state := model.UserStateRetiredSAST
	if input.State != nil {
		state = model.UserState(strings.TrimSpace(*input.State))
		if !validState(state) {
			return validatedCreate{}, newError(ErrInvalidInput, "state 取值非法", nil)
		}
		// A closed account has no sessions by construction; creating one already
		// closed would skip every revocation path those transitions carry.
		if state == model.UserStateDeleted {
			return validatedCreate{}, newError(ErrStateConflict,
				"新建账号不能直接处于已注销状态", nil)
		}
	}
	result.state = state

	return result, nil
}
