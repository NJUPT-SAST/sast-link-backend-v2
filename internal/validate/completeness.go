package validate

import "strings"

// Field names for the incomplete-profile report. They are the JSON field names
// of PUT /user/profile, so a client can map a reported field straight onto the
// form control that fixes it.
const (
	FieldName        = "name"
	FieldPhoneNumber = "phone_number"
	FieldMajor       = "major"
)

// IsBlank reports whether value is empty or consists only of whitespace.
//
// This is the Go half of a rule that also exists in SQL, as V010's
// sl_profile_is_blank. The two must agree exactly: the SQL side decides whether
// an account is flagged as incomplete, and this side decides whether the user's
// attempted fix is accepted. A rule that is stricter here than there produces an
// account the frontend calls complete and every edit rejects; the reverse
// produces a prompt the user cannot clear. TestProfileCompletenessMatchesSQL
// feeds both the same inputs.
//
// strings.TrimSpace is the reference implementation rather than a hand-rolled
// loop because it is what every write path in this service already applies
// before storing these columns.
func IsBlank(value string) bool {
	return strings.TrimSpace(value) == ""
}

// IncompleteProfileFields returns the required "user" fields that still hold
// unusable values, in a stable order.
//
// Two shapes of legacy debris are reported, matching V010's generated column:
//
//   - a blank required field, which NOT NULL never excluded because the columns
//     have no DEFAULT (or, for major, DEFAULT ”)
//   - a name equal to the student ID, which the previous database's import used
//     as a placeholder
//
// The name/studentID comparison is case-insensitive because the imported rows
// hold both 'B24040525' and 'b24040525' against the same student ID, and a
// case-sensitive test would pass the lowercase half.
//
// qq_number is not reported. It is empty for every imported account because the
// previous database had no such field, so reporting it would mark the entire
// table incomplete forever and make the signal useless. college is not reported
// either: '其他' is a valid choice and nothing distinguishes an import default
// from a deliberate selection, so it would raise a prompt the user cannot
// honestly clear.
//
// A nil return means the account is complete. Callers must treat this as a
// display hint only - it is never an authorization input.
func IncompleteProfileFields(name, phoneNumber, major, studentID string) []string {
	var fields []string
	if IsBlank(name) || strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(studentID)) {
		fields = append(fields, FieldName)
	}
	if IsBlank(phoneNumber) {
		fields = append(fields, FieldPhoneNumber)
	}
	if IsBlank(major) {
		fields = append(fields, FieldMajor)
	}
	return fields
}
