package validate

import (
	"strings"
	"testing"
)

// An address becomes a Redis key segment and a rate-limit subject before the
// mailer ever validates it, so whitespace has to be rejected at the input layer
// rather than left for SMTP. Interior whitespace also breaks identity: "a b@x"
// and "ab@x" name one mailbox but occupy two verification-code and rate-limit
// buckets, so a caller could mint extra codes for an address by padding it.
//
// The subtle cases are the ones a `r < 0x20` test misses: U+0020 sits just
// outside it, and the four marked below additionally satisfy mail.ParseAddress,
// so they used to reach the SMTP send and surface as a 50001 delivery failure
// instead of an input error.
func TestEmailFormatRejectsWhitespace(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{name: "ascii space in local part", email: "a b@njupt.edu.cn"},
		{name: "ascii space before at", email: "ab @njupt.edu.cn"},
		{name: "tab", email: "a\tb@njupt.edu.cn"},
		{name: "carriage return", email: "a\rb@njupt.edu.cn"},
		{name: "newline", email: "a\nb@njupt.edu.cn"},
		{name: "NBSP", email: "a\u00a0b@njupt.edu.cn"},
		{name: "ideographic space", email: "a\u3000b@njupt.edu.cn"},
		{name: "em space", email: "a\u2003b@njupt.edu.cn"},
		{name: "ogham space mark", email: "a\u1680b@njupt.edu.cn"},
		{name: "line separator", email: "a\u2028b@njupt.edu.cn"},
		{name: "paragraph separator", email: "a\u2029b@njupt.edu.cn"},
		{name: "zero-width space", email: "a\u200bb@njupt.edu.cn"},
		{name: "zero-width non-joiner", email: "a\u200cb@njupt.edu.cn"},
		{name: "zero-width joiner", email: "a\u200db@njupt.edu.cn"},
		{name: "BOM", email: "a\ufeffb@njupt.edu.cn"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if EmailFormat(test.email) {
				t.Errorf("EmailFormat(%q) = true, want false", test.email)
			}
		})
	}
}

// The tightened check must not start rejecting addresses the university and
// SAST actually issue.
func TestEmailFormatAcceptsRealAddresses(t *testing.T) {
	for _, email := range []string{
		"B24040101@njupt.edu.cn",
		"zhang.san@njupt.edu.cn",
		"user_name-x@njupt.edu.cn",
		"a.b+tag@sast.fun",
	} {
		if !EmailFormat(email) {
			t.Errorf("EmailFormat(%q) = false, want true", email)
		}
	}
}

// C1 controls (0x80-0x9f) are as unwelcome as C0: U+0085 NEL terminates a line for
// some consumers, so it splits a log record or a rendered value exactly the way a
// bare CR does. The admin console's email guard used to miss this whole range.
func TestEmailFormatRejectsC1Controls(t *testing.T) {
	for _, testCase := range []struct{ name, email string }{
		{"NEL", "a\u0085b@njupt.edu.cn"},
		{"C1 start", "a\u0080b@njupt.edu.cn"},
		{"C1 end", "a\u009fb@njupt.edu.cn"},
		{"DEL", "a\u007fb@njupt.edu.cn"},
		{"NUL", "a\u0000b@njupt.edu.cn"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if EmailFormat(testCase.email) {
				t.Errorf("EmailFormat(%q) = true, want false", testCase.email)
			}
		})
	}
}

// Structural defects, independent of the character set.
func TestEmailFormatRejectsMalformedStructure(t *testing.T) {
	for _, testCase := range []struct{ name, email string }{
		{"empty", ""},
		{"no at", "abnjupt.edu.cn"},
		{"two ats", "a@b@njupt.edu.cn"},
		{"empty local part", "@njupt.edu.cn"},
		{"trailing at", "ab@"},
		{"undotted domain", "ab@localhost"},
		{"leading dot in domain", "ab@.njupt.edu.cn"},
		{"trailing dot in domain", "ab@njupt.edu.cn."},
		{"consecutive dots", "ab@njupt..edu.cn"},
		{"comma separator", "a,b@njupt.edu.cn"},
		{"display-name brackets", "<ab@njupt.edu.cn>"},
		{"semicolon", "a;b@njupt.edu.cn"},
		{"quote", "a" + string(rune(34)) + "b@njupt.edu.cn"},
		{"backslash", "a" + string(rune(92)) + "b@njupt.edu.cn"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if EmailFormat(testCase.email) {
				t.Errorf("EmailFormat(%q) = true, want false", testCase.email)
			}
		})
	}
}

func TestIsLoginEmailDomain(t *testing.T) {
	for _, testCase := range []struct {
		email string
		want  bool
	}{
		{"b24040101@njupt.edu.cn", true},
		{"someone@sast.fun", true},
		// A domain that merely contains an allowed one must not pass: the V001 trigger
		// matches on the suffix, so anything else raises in the database instead.
		{"someone@njupt.edu.cn.evil.com", false},
		{"someone@gmail.com", false},
		{"someone@sast.fun.evil.com", false},
		{"", false},
	} {
		if got := IsLoginEmailDomain(testCase.email); got != testCase.want {
			t.Errorf("IsLoginEmailDomain(%q) = %v, want %v", testCase.email, got, testCase.want)
		}
	}
}

// PostgreSQL bounds varchar in characters, so a byte-length check would reject a
// name that actually fits.
func TestWithinLengthCountsCharactersNotBytes(t *testing.T) {
	twoHundredChinese := strings.Repeat("张", 200)
	if !WithinLength(twoHundredChinese, MaxNameLength) {
		t.Fatalf("200 Chinese characters (%d bytes) rejected against varchar(%d)",
			len(twoHundredChinese), MaxNameLength)
	}
	if WithinLength(strings.Repeat("a", MaxNameLength+1), MaxNameLength) {
		t.Fatal("a value one character over the limit was accepted")
	}
	if !WithinLength(strings.Repeat("a", MaxNameLength), MaxNameLength) {
		t.Fatal("a value exactly at the limit was rejected")
	}
}
