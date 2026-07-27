package session

import "testing"

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
func TestValidEmailFormatRejectsWhitespace(t *testing.T) {
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
			if validEmailFormat(test.email) {
				t.Errorf("validEmailFormat(%q) = true, want false", test.email)
			}
		})
	}
}

// The tightened check must not start rejecting addresses the university and
// SAST actually issue.
func TestValidEmailFormatAcceptsRealAddresses(t *testing.T) {
	for _, email := range []string{
		"B24040101@njupt.edu.cn",
		"zhang.san@njupt.edu.cn",
		"user_name-x@njupt.edu.cn",
		"a.b+tag@sast.fun",
	} {
		if !validEmailFormat(email) {
			t.Errorf("validEmailFormat(%q) = false, want true", email)
		}
	}
}
