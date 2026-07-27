package mailer

import (
	"testing"
)

func TestSanitizeAddressAcceptsAddrSpec(t *testing.T) {
	got, err := sanitizeAddress("user@njupt.edu.cn")
	if err != nil || got != "user@njupt.edu.cn" {
		t.Fatalf("got=%q err=%v, want passthrough addr-spec", got, err)
	}
}

func TestSanitizeAddressStripsDisplayName(t *testing.T) {
	// mail.ParseAddress accepts a display name; the returned addr-spec must
	// still be the bare address, free of the surrounding angle brackets and
	// any attacker-controlled name.
	got, err := sanitizeAddress("Evil <user@njupt.edu.cn>")
	if err != nil || got != "user@njupt.edu.cn" {
		t.Fatalf("got=%q err=%v, want bare addr-spec", got, err)
	}
}

func TestSanitizeAddressRejectsHeaderInjection(t *testing.T) {
	// A CRLF in the address would terminate the To header and let the rest
	// of the string become a smuggled BCC. This must not reach buildMessage.
	for _, bad := range []string{
		"user@njupt.edu.cn\r\nBcc: attacker@evil.example",
		"user@njupt.edu.cn\nBcc: attacker@evil.example",
		"user@njupt.edu.cn,attacker@evil.example",
		"user",
		"@njupt.edu.cn",
		"",
	} {
		if _, err := sanitizeAddress(bad); err == nil {
			t.Errorf("sanitizeAddress(%q) = nil err, want rejection", bad)
		}
	}
}

func TestSanitizeAddressTrimsSurroundingWhitespace(t *testing.T) {
	// Trailing whitespace is normalized away by TrimSpace and the returned
	// addr-spec is clean, so it is safe to accept.
	got, err := sanitizeAddress("  user@njupt.edu.cn  ")
	if err != nil || got != "user@njupt.edu.cn" {
		t.Fatalf("got=%q err=%v, want trimmed addr-spec", got, err)
	}
}

func TestSanitizeRecipientsRejectsAnyBadAddress(t *testing.T) {
	if _, err := sanitizeRecipients([]string{"user@njupt.edu.cn", "evil\r\nBcc: x@y.example"}); err == nil {
		t.Fatal("sanitizeRecipients accepted a header-injection recipient")
	}
	if got, err := sanitizeRecipients([]string{"a@sast.fun", "b@njupt.edu.cn"}); err != nil || len(got) != 2 {
		t.Fatalf("got=%v err=%v, want two sanitized addresses", got, err)
	}
}
