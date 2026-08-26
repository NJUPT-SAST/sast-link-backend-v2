package validate

import "strings"

// Field names for the incomplete-profile report. They are the JSON field names
// of PUT /user/profile, so a client can map a reported field straight onto the
// form control that fixes it.
const (
	FieldName        = "name"
	FieldPhoneNumber = "phone_number"
	FieldQQNumber    = "qq_number"
	FieldMajor       = "major"
)

// IsBlank reports whether value is empty or consists only of whitespace.
//
// This is the Go half of a rule that also exists in SQL, as V010's
// sl_profile_is_blank, and the two must agree exactly:
// TestProfileCompletenessMatchesSQL feeds both the same inputs. strings.TrimSpace
// is the reference implementation, matching what every write path applies before
// storing these columns.
func IsBlank(value string) bool {
	return strings.TrimSpace(value) == ""
}

// IncompleteProfileFields returns the required "user" fields that still hold
// unusable values, in a stable order, matching V010's generated column:
// a blank required banner field (name, phone_number, qq_number, major) or a name
// equal to the student ID (compared case-insensitively). college is deliberately
// not reported — '其他' is a valid choice — and student_id, login_email and
// password are identifiers or credentials rather than profile fields.
//
// A nil return means the account is complete. Callers must treat this as a
// display hint only — it is never an authorization input.
func IncompleteProfileFields(name, phoneNumber, qqNumber, major, studentID string) []string {
	var fields []string
	if IsBlank(name) || strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(studentID)) {
		fields = append(fields, FieldName)
	}
	if IsBlank(phoneNumber) {
		fields = append(fields, FieldPhoneNumber)
	}
	if IsBlank(qqNumber) {
		fields = append(fields, FieldQQNumber)
	}
	if IsBlank(major) {
		fields = append(fields, FieldMajor)
	}
	return fields
}
