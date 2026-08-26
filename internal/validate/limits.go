package validate

import "unicode/utf8"

// Column widths from V001, rejecting an over-long value at the input layer so it
// fails as a 400 naming the field instead of an opaque PostgreSQL 500. These are
// schema facts, not per-service policy, so they live in one place: a widened
// column must find every check that bounds it.
const (
	MaxNameLength        = 255
	MaxPhoneNumberLength = 20
	MaxPageSize          = 100
	MaxQQNumberLength    = 20
	MaxStudentIDLength   = 50
	MaxMajorLength       = 50
	MaxLoginEmailLength  = 255
	MaxNicknameLength    = 255
	MaxIntroLength       = 255
	MaxDisplayEmailLen   = 255
	MaxURLLength         = 512
)

// WithinLength reports whether value fits in a varchar(limit). PostgreSQL counts
// characters, not bytes, so width is measured in runes, not len().
func WithinLength(value string, limit int) bool {
	return utf8.RuneCountInString(value) <= limit
}
