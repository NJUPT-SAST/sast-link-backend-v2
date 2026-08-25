package validate

// Field-level checks shared by the account-provisioning paths.
//
// Two services apply the same "required string" rule: the admin console's
// POST /admin/users and the alumni account-request ticket. They report it
// differently - one is an authenticated console write, the other an anonymous
// submission whose error copy must not carry console semantics - so what is
// shared here is the rule, not the message. A Reason names why a value was
// refused and the caller maps it onto its own error type, error code and
// wording.
//
// Deliberately no message: a shared one would put a service's copy on another
// service's surface, and the anonymous endpoint would answer with strings
// written for administrators.

import "strings"

// Reason is why a field-level check refused a value.
type Reason string

const (
	// ReasonRequired is an empty value where one is mandatory. Emptiness is decided
	// after trimming, so a value holding only whitespace is required-empty rather
	// than invalid: something was typed, it just carries no content.
	ReasonRequired Reason = "required"
	// ReasonTooLong exceeds the V001 column width, counted in runes rather than
	// bytes for the reason WithinLength documents.
	ReasonTooLong Reason = "too_long"
	// ReasonInvalid holds a C0/C1 control character. Named for the caller-facing
	// category rather than the offending codepoint class: the submitter needs to
	// know the value is unacceptable, not which range it fell in.
	ReasonInvalid Reason = "invalid"
)

// FieldError names the refused field and why.
//
// Field carries the JSON field name, the same convention as
// IncompleteProfileFields, so a client can map a report straight onto the form
// control that fixes it. It holds no message and no HTTP status: those belong to
// the service that received the request.
type FieldError struct {
	Field  string
	Reason Reason
}

// RequiredField validates a mandatory string and returns it trimmed.
//
// The three checks travel together on purpose. Every provisioning path applies
// presence, width and control-character rejection to the same columns, and
// splitting them into separate helpers is how a call site ends up omitting the
// control-character test - the one whose absence is invisible, since a name
// holding a stray CR renders as ordinary text and misbehaves only once it
// reaches an audit log or a mail header.
//
// The returned value is what the caller must store. Trimming here and storing
// the raw input elsewhere would mean the length that was checked is not the
// length that gets written.
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
