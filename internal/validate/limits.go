package validate

import "unicode/utf8"

// Column widths from V001. Rejecting an over-long value at the input layer turns a
// PostgreSQL "value too long for type character varying(n)" — which surfaces as an
// opaque 500 naming no field — into a 400 that names it.
//
// These are schema facts, not per-service policy, so they live in one place: an
// ALTER TABLE that widens a column has to find every check that bounds it, and a
// copy left behind silently keeps rejecting values the database would now accept.
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

// WithinLength reports whether value fits in a varchar(limit).
//
// PostgreSQL counts characters, not bytes, so a name of 200 Chinese characters fits
// varchar(255) despite being 600 bytes. Using len() here would reject it.
func WithinLength(value string, limit int) bool {
	return utf8.RuneCountInString(value) <= limit
}

// PreallocateRows returns a slice capacity safe to reserve for a page of limit rows.
//
// A repository must not size an allocation from a caller-supplied limit directly. Its
// list methods are exported and reachable by any future caller, not only through the
// service that clamps page_size, and the allocation happens before a single row is
// read: a limit of 50 million reserves gigabytes for a query that may return nothing.
// Capping at the page size the contract actually serves costs nothing, since a larger
// limit could never fill the extra capacity through any supported request.
func PreallocateRows(limit int) int {
	if limit <= 0 {
		return 0
	}
	return min(limit, MaxPageSize)
}
