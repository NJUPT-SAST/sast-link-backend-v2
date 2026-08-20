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
//   - a blank required banner field (name, phone_number, qq_number, major),
//     which NOT NULL never excluded because the columns have no DEFAULT (or, for
//     major, an empty-string DEFAULT)
//   - a name equal to the student ID, which the previous database's import used
//     as a placeholder
//
// Every NOT NULL banner field the user can fill in through PUT /user/profile is
// treated alike. qq_number is included even though the import left it empty for
// every row: the import reflects the previous database, not today's production,
// and a first login prompting to collect the field once is the point of the
// guided completion. college is not reported: '其他' is a valid choice and
// nothing distinguishes an import default from a deliberate selection, so it
// would raise a prompt the user cannot honestly clear. student_id, login_email
// and password are identifiers or credentials rather than profile fields, so
// they are out of scope here.
//
// The name/studentID comparison is case-insensitive because the imported rows
// hold both 'B24040525' and 'b24040525' against the same student ID, and a
// case-sensitive test would pass the lowercase half.
//
// A nil return means the account is complete. Callers must treat this as a
// display hint only - it is never an authorization input.
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
