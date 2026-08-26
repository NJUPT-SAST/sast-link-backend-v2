// Package validate holds the input rules that more than one service must apply
// identically. They live in one place because two copies of the same rule drift,
// and the drift is invisible until it locks someone out.
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
// corruption: it rejects control characters (notably CR/LF), address separators,
// display-name brackets, and any invisible codepoint, and requires exactly one @
// with a dotted domain. This is defense in depth ahead of the mailer's own
// mail.ParseAddress check and keeps Redis keys and audit detail free of
// unprintable bytes.
//
// Whitespace is rejected everywhere, not just at the ends: the address becomes a
// Redis key segment and a rate-limit subject before the mailer sees it, and
// whitespace variants survive mail.ParseAddress.
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

// HasControlCharacter reports whether value contains a C0 or C1 control character
// (0x00-0x1f, 0x7f, 0x80-0x9f): C1 matters because U+0085 NEL terminates a line
// for some consumers. Interior spaces are deliberately allowed — names, intros and
// majors contain them, and callers already trim the edges.
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

// StripSubaddress returns the delivery mailbox of an email, dropping the "+tag"
// subaddressing suffix (foo+bar@example.com -> foo@example.com). Verification-code
// and rate-limit keys are keyed by this mailbox, so alias variants of one inbox
// cannot mint unbounded distinct Redis keys. Dots are deliberately left alone:
// whether dots conflate addresses varies by provider, so collapsing them would
// collide distinct mailboxes.
func StripSubaddress(email string) string {
	at := strings.IndexByte(email, '@')
	if at < 0 {
		return email
	}
	local := email[:at]
	if plus := strings.IndexByte(local, '+'); plus >= 0 {
		local = local[:plus]
	}
	return local + email[at:]
}
