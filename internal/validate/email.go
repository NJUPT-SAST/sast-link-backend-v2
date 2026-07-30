// Package validate holds the input rules that more than one service must apply
// identically.
//
// Nothing here is about any one use case: these are facts about the V001 schema and
// about what an email address may contain. They live in one place because two copies
// of the same rule drift, and the drift is invisible until it locks someone out —
// an administrator writing a login_email that the login flow's stricter checker
// rejects produces an account whose owner can never authenticate, and the console
// renders the address as perfectly ordinary the whole time.
package validate

import (
	"strings"
	"unicode"
)

// Invisible codepoints that unicode.IsSpace does not classify as space. Named
// rather than written as literals so they stay reviewable in source.
const (
	zeroWidthSpace     = '\u200b'
	zeroWidthNonJoiner = '\u200c'
	zeroWidthJoiner    = '\u200d'
	byteOrderMark      = '\ufeff'
)

// loginEmailDomains are the only domains an account's login address may use. The
// V001 trigger auto_set_email_type derives email_type from these two and raises for
// anything else, so a write that gets past this check fails in the database with a
// bare exception instead of a message naming the rule.
var loginEmailDomains = []string{"@njupt.edu.cn", "@sast.fun"}

// EmailFormat is the input-layer guard against SMTP header injection and key/audit
// corruption. It rejects control characters (notably CR/LF, which the go-playground
// "email" validator lets through), address separators, display-name brackets, and
// any invisible codepoint, and it requires exactly one @ with a dotted domain. This
// is defense in depth ahead of the mailer's own mail.ParseAddress check; it also
// keeps Redis keys and audit detail free of unprintable bytes.
//
// Whitespace is rejected everywhere, not just at the ends. An address is used as a
// Redis key segment and a rate-limit subject before the mailer ever sees it, so
// letting whitespace through means "a b@x" and "ab@x" occupy different buckets while
// naming the same mailbox. A bare `r < 0x20` test misses this: U+0020 sits just
// outside it, and NBSP, U+3000, U+200B and U+2028 are far above it. Those four also
// survive mail.ParseAddress, so the request would travel all the way to SMTP before
// failing — surfacing a delivery error for what is really malformed input.
func EmailFormat(email string) bool {
	if email == "" || strings.Count(email, "@") != 1 {
		return false
	}
	at := strings.IndexByte(email, '@')
	if at == 0 || at == len(email)-1 {
		return false
	}
	if strings.ContainsAny(email, ",;:<>()[]\\\"") {
		return false
	}
	for _, symbol := range email {
		switch symbol {
		case zeroWidthSpace, zeroWidthNonJoiner, zeroWidthJoiner, byteOrderMark:
			return false
		}
		if unicode.IsSpace(symbol) {
			return false
		}
	}
	if HasControlCharacter(email) {
		return false
	}
	// A domain needs a dot, and no label may be empty.
	domain := email[at+1:]
	return strings.Contains(domain, ".") &&
		!strings.HasPrefix(domain, ".") && !strings.HasSuffix(domain, ".") &&
		!strings.Contains(domain, "..")
}

// IsLoginEmailDomain reports whether email ends in a domain accounts may log in
// with. It does not validate the rest of the address; pair it with EmailFormat.
func IsLoginEmailDomain(email string) bool {
	for _, domain := range loginEmailDomains {
		if strings.HasSuffix(email, domain) {
			return true
		}
	}
	return false
}

// HasControlCharacter reports whether value contains a C0 or C1 control character.
//
// PostgreSQL rejects U+0000 in text at the protocol level (SQLSTATE 22021), which is
// not a unique violation and so surfaces as a 500 naming no field. The other control
// characters do store, but they travel into audit logs and onto the public card,
// where a stray CR or LF splits a log line or a rendered value. C1 (0x80-0x9f)
// matters as much as C0: U+0085 NEL terminates a line for some consumers. Display
// text has no legitimate use for any of them.
//
// Interior spaces are deliberately allowed: names, intros and majors contain them,
// and callers already trim the edges.
func HasControlCharacter(value string) bool {
	for _, symbol := range value {
		if symbol < 0x20 || symbol == 0x7f {
			return true
		}
		if symbol >= 0x80 && symbol <= 0x9f {
			return true
		}
	}
	return false
}
