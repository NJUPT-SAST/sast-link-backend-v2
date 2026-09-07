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

// fieldUnusable reports whether a required profile field holds a shape the
// write path rejects: blank, over the column width, or a C0/C1 control
// character. It mirrors the input-layer rule so a legacy value cannot hide
// from the completion prompt while still blocking a profile edit.
func fieldUnusable(value string, limit int) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == "" || !WithinLength(trimmed, limit) || HasControlCharacter(trimmed)
}

// IncompleteProfileFields returns the required "user" fields that still hold
// unusable values, in a stable order, matching the generated column:
// a blank, over-long or control-character-bearing required banner field
// (name, phone_number, qq_number, major) or a name equal to the student ID
// (compared case-insensitively). college is deliberately not reported — '其他'
// is a valid choice — and student_id, login_email and password are identifiers
// or credentials rather than profile fields.
//
// A nil return means the account is complete. Callers must treat this as a
// display hint only — it is never an authorization input.
func IncompleteProfileFields(name, phoneNumber, qqNumber, major, studentID string) []string {
	var fields []string
	if fieldUnusable(name, MaxNameLength) || strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(studentID)) {
		fields = append(fields, FieldName)
	}
	if fieldUnusable(phoneNumber, MaxPhoneNumberLength) {
		fields = append(fields, FieldPhoneNumber)
	}
	if fieldUnusable(qqNumber, MaxQQNumberLength) {
		fields = append(fields, FieldQQNumber)
	}
	if fieldUnusable(major, MaxMajorLength) {
		fields = append(fields, FieldMajor)
	}
	return fields
}
