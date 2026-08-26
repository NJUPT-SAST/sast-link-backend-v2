package validate

// Field-level checks shared by the account-provisioning paths (the admin console's
// POST /admin/users and the alumni account-request ticket). What is shared is the
// rule, not the message: a Reason names why a value was refused, and the caller
// maps it onto its own error type, code and wording.

import "strings"

// Reason is why a field-level check refused a value.
type Reason string

const (
	// ReasonRequired is an empty value where one is mandatory; emptiness is
	// decided after trimming.
	ReasonRequired Reason = "required"
	// ReasonTooLong exceeds the V001 column width, counted in runes rather than
	// bytes for the reason WithinLength documents.
	ReasonTooLong Reason = "too_long"
	// ReasonInvalid holds a C0/C1 control character, named for the caller-facing
	// category rather than the offending codepoint range.
	ReasonInvalid Reason = "invalid"
)

// FieldError names the refused field and why. Field carries the JSON field name,
// the same convention as IncompleteProfileFields; there is no message and no HTTP
// status — those belong to the service that received the request.
type FieldError struct {
	Field  string
	Reason Reason
}

// RequiredField validates a mandatory string and returns it trimmed.
//
// The presence, width and control-character checks travel together, so a call site
// cannot omit the control-character test — its absence is invisible.
//
// The returned value is what the caller must store, so the length that was checked
// is the length that gets written.
func RequiredField(field, raw string, limit int) (string, *FieldError) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", &FieldError{Field: field, Reason: ReasonRequired}
	}
	return validateTrimmed(field, value, limit)
}

// OptionalField is RequiredField for a value that may legitimately be absent.
//
// An empty result is a successful outcome, so callers must not treat "" as a
// failure. A value that is present still has to fit the column and stay free of
// control characters.
func OptionalField(field, raw string, limit int) (string, *FieldError) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	return validateTrimmed(field, value, limit)
}

// validateTrimmed applies the width and control-character rules to an
// already-trimmed, non-empty value.
func validateTrimmed(field, value string, limit int) (string, *FieldError) {
	if !WithinLength(value, limit) {
		return "", &FieldError{Field: field, Reason: ReasonTooLong}
	}
	if HasControlCharacter(value) {
		return "", &FieldError{Field: field, Reason: ReasonInvalid}
	}
	return value, nil
}
