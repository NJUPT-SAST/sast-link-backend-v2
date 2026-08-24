package alumnirequest

import (
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// Length ceilings for the fields that exist only on a ticket and have no V001
// column behind them. The rest are bounded by the widths in internal/validate,
// because they are copied into "user" on approval.
const (
	maxJoinYearLength       = 32
	maxDepartmentNoteLength = 255
	maxNoteLength           = 1000
	maxRejectReasonLength   = 500
)

// The messages below are built from a fixed field name, never from a submitted
// value. This service's submit path is unauthenticated, so reflecting input back
// would make it a reflection point for anyone who can reach the endpoint.
func fieldRequiredMessage(field string) string { return field + " 不能为空" }
func fieldTooLongMessage(field string) string  { return field + " 长度超出限制" }
func fieldInvalidMessage(field string) string  { return field + " 含非法字符" }

// fieldError maps a validate.FieldError onto this service's invalid-input error.
//
// The rule is shared with the console through internal/validate; the wording is
// not. An anonymous endpoint must not answer with copy written for
// administrators.
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

// validatedSubmit holds the normalized submission.
type validatedSubmit struct {
	name           string
	studentID      string
	loginEmail     string
	personalEmail  string
	phoneNumber    string
	qqNumber       string
	college        model.College
	major          string
	joinYear       string
	departmentNote string
	note           string
}

// validateSubmit checks a submission.
//
// Stricter than the console's provisioning in two ways, both traceable to V010's
// profile_needs_completion generated column:
//
//   - major is required. The console may leave it empty, but an account created
//     from a ticket with a blank major is flagged incomplete the moment it exists,
//     and the applicant is sent to a completion page on their first login — for a
//     field they were never asked for.
//   - name must not equal student_id. That was the previous database's placeholder
//     for a missing name, and it is the second shape the generated column treats
//     as debris.
//
// The name/student_id comparison is not written here. It comes from
// validate.IncompleteProfileFields, whose agreement with the SQL is what
// TestProfileCompletenessMatchesSQL enforces — a local reimplementation would be
// a third copy of the rule with nothing checking it against V010.
func validateSubmit(input SubmitInput) (validatedSubmit, error) {
	var result validatedSubmit

	required := []struct {
		field  string
		value  string
		limit  int
		target *string
	}{
		{"name", input.Name, validate.MaxNameLength, &result.name},
		{"student_id", input.StudentID, validate.MaxStudentIDLength, &result.studentID},
		{"phone_number", input.PhoneNumber, validate.MaxPhoneNumberLength, &result.phoneNumber},
		{"qq_number", input.QQNumber, validate.MaxQQNumberLength, &result.qqNumber},
		// Required here, optional on the console path. See the doc comment.
		{"major", input.Major, validate.MaxMajorLength, &result.major},
		{"join_year", input.JoinYear, maxJoinYearLength, &result.joinYear},
	}
	for _, field := range required {
		value, refused := validate.RequiredField(field.field, field.value, field.limit)
		if refused != nil {
			return validatedSubmit{}, fieldError(refused)
		}
		*field.target = value
	}

	optional := []struct {
		field  string
		value  string
		limit  int
		target *string
	}{
		{"department_note", input.DepartmentNote, maxDepartmentNoteLength, &result.departmentNote},
		{"note", input.Note, maxNoteLength, &result.note},
	}
	for _, field := range optional {
		value, refused := validate.OptionalField(field.field, field.value, field.limit)
		if refused != nil {
			return validatedSubmit{}, fieldError(refused)
		}
		*field.target = value
	}

	loginEmail, err := validateLoginEmail(input.LoginEmail)
	if err != nil {
		return validatedSubmit{}, err
	}
	result.loginEmail = loginEmail

	personalEmail, err := validatePersonalEmail(input.PersonalEmail, loginEmail)
	if err != nil {
		return validatedSubmit{}, err
	}
	result.personalEmail = personalEmail

	college := model.CollegeOther
	if input.College != nil {
		college = model.College(strings.TrimSpace(*input.College))
		if !college.Valid() {
			return validatedSubmit{}, newError(ErrInvalidInput, "college 取值非法", nil)
		}
	}
	result.college = college

	// The completeness rule is checked against the normalized values, which is what
	// approval will write. Checking the raw input would let "  B24040525  " pass and
	// then store a name the generated column flags.
	if incomplete := validate.IncompleteProfileFields(
		result.name, result.phoneNumber, result.qqNumber, result.major, result.studentID,
	); len(incomplete) > 0 {
		// The only reachable case at this point is name == student_id: the four
		// blankness checks were already satisfied by RequiredField above. Naming the
		// field rather than the rule keeps the message actionable.
		return validatedSubmit{}, newError(ErrInvalidInput, "name 不能与 student_id 相同", nil)
	}

	return result, nil
}

// validateLoginEmail checks the school address that becomes the account's login
// identity.
//
// The domain allow-list is not relaxed for this flow even though the whole point
// is that the mailbox no longer receives mail. login_email is what V001's
// auto_set_email_type trigger derives email_type from, so an address outside the
// list fails in the database with a bare exception. The applicant's reachable
// address is carried separately as personal_email.
func validateLoginEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" {
		return "", newError(ErrInvalidInput, fieldRequiredMessage("login_email"), nil)
	}
	if !validate.WithinLength(email, validate.MaxLoginEmailLength) {
		return "", newError(ErrInvalidInput, fieldTooLongMessage("login_email"), nil)
	}
	if !validate.EmailFormat(email) {
		return "", newError(ErrInvalidInput, "login_email 格式非法", nil)
	}
	if !validate.IsLoginEmailDomain(email) {
		return "", newError(ErrInvalidInput, "login_email 必须是学校或社团邮箱", nil)
	}
	return email, nil
}

// validatePersonalEmail checks the reachable third-party address.
//
// No domain restriction: being outside the school domains is the entire reason it
// is here. It must differ from the login email because V005's two triggers forbid
// one address from being both a login_email and an other_mail identity, and
// rejecting it now names the field instead of surfacing a constraint violation at
// approval time.
func validatePersonalEmail(raw, loginEmail string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" {
		return "", newError(ErrInvalidInput, fieldRequiredMessage("personal_email"), nil)
	}
	if !validate.WithinLength(email, validate.MaxLoginEmailLength) {
		return "", newError(ErrInvalidInput, fieldTooLongMessage("personal_email"), nil)
	}
	if !validate.EmailFormat(email) {
		return "", newError(ErrInvalidInput, "personal_email 格式非法", nil)
	}
	if email == loginEmail {
		return "", newError(ErrInvalidInput, "personal_email 不能与 login_email 相同", nil)
	}
	return email, nil
}

// validateRejectReason checks the reason that reaches the applicant by email.
//
// Required: a rejection with no explanation gives the applicant nothing to
// correct, and the flow's whole premise is that they can fix their details and
// resubmit.
func validateRejectReason(raw string) (string, error) {
	reason, refused := validate.RequiredField("reject_reason", raw, maxRejectReasonLength)
	if refused != nil {
		return "", fieldError(refused)
	}
	return reason, nil
}

// parseStatus resolves an optional status filter.
//
// An unrecognized value is refused rather than ignored. Silently dropping it
// would answer a filtered query with the unfiltered set, which reads as "there
// are no pending tickets" when the real answer is "you misspelled pending".
func parseStatus(raw *string) (*model.AlumniRequestStatus, error) {
	if raw == nil {
		return nil, nil
	}
	trimmed := strings.TrimSpace(*raw)
	if trimmed == "" {
		return nil, nil
	}
	status := model.AlumniRequestStatus(trimmed)
	if !status.Valid() {
		return nil, newError(ErrInvalidInput, "status 取值非法", nil)
	}
	return &status, nil
}
