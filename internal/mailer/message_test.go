package mailer

import (
	"strings"
	"testing"
)

// CodeQL flags w.Write(msg) as go/email-injection because it cannot see what
// buildMessage does to its inputs. These tests pin down the two boundaries that
// actually matter, so the suppression rests on asserted behaviour.
//
// Note what is NOT claimed: quoted-printable preserves CRLF, so a newline in the
// body does appear as a newline in the output. That is harmless — it lands inside
// an established MIME part, where a line break is content, not structure. The
// exploitable versions would be escaping into the header block or forging a part
// separator, and both are closed below.
func TestBuildMessageKeepsInjectedHeadersOutOfTheHeaderBlock(t *testing.T) {
	const payload = "code\r\nBcc: attacker@evil.example\r\n\r\nInjected body"

	rendered := buildOrFail(t, payload, payload, payload)

	separator := strings.Index(rendered, "\r\n\r\n")
	if separator < 0 {
		t.Fatal("message has no header/body separator")
	}
	headers := rendered[:separator]

	// Check per line, not across the block: the Q-encoded subject legitimately
	// contains the literal text "Bcc:" as encoded payload, which is inert. What
	// would matter is a line that starts with it.
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Errorf("payload injected a Bcc header line %q in:\n%s", line, headers)
		}
	}
	// Q-encoding is what neutralizes the subject: the CRLF must survive only as
	// an encoded token, never as a real line break.
	if !strings.Contains(headers, "=0D=0A") {
		t.Errorf("subject CRLF was not Q-encoded:\n%s", headers)
	}
	for _, line := range strings.Split(headers, "\r\n") {
		if line == "" {
			continue
		}
		switch strings.SplitN(line, ":", 2)[0] {
		case "From", "To", "Subject", "MIME-Version", "Auto-Submitted",
			"Content-Type", "Content-Transfer-Encoding":
		default:
			t.Errorf("unexpected header line %q in:\n%s", line, headers)
		}
	}
}

// A body cannot close its own part or open a new one, because the boundary is
// random per message and therefore unguessable by whoever supplies the body.
func TestBuildMessageBodyCannotForgeMimeBoundary(t *testing.T) {
	first := mimeBoundaryOf(t, buildOrFail(t, "subject", "text", "html"))
	second := mimeBoundaryOf(t, buildOrFail(t, "subject", "text", "html"))
	if first == second {
		t.Fatalf("boundary is stable across messages (%q); a body could predict it", first)
	}

	forged := "x\r\n--" + first + "\r\nContent-Type: text/plain\r\n\r\nforged"
	rendered := buildOrFail(t, "subject", forged, forged)
	boundary := mimeBoundaryOf(t, rendered)

	// Exactly three occurrences: the text part, the html part, and the closing
	// delimiter. A successful forgery would add more.
	if count := strings.Count(rendered, "--"+boundary); count != 3 {
		t.Errorf("boundary occurrences = %d, want 3 (text, html, close)", count)
	}
}

func buildOrFail(t *testing.T, subject, text, html string) string {
	t.Helper()
	msg, err := buildMessage("noreply@sast.fun", []string{"user@njupt.edu.cn"}, subject, text, html)
	if err != nil {
		t.Fatalf("buildMessage() error = %v", err)
	}
	return string(msg)
}

func mimeBoundaryOf(t *testing.T, rendered string) string {
	t.Helper()
	const marker = `boundary="`
	start := strings.Index(rendered, marker)
	if start < 0 {
		t.Fatal("message declares no MIME boundary")
	}
	start += len(marker)
	end := strings.Index(rendered[start:], `"`)
	if end < 0 {
		t.Fatal("unterminated MIME boundary declaration")
	}
	return rendered[start : start+end]
}

// Recipients are validated before buildMessage ever sees them; this is the check
// that keeps a CRLF address out of the To header.
func TestSanitizeRecipientsRejectsCRLFAddress(t *testing.T) {
	if _, err := sanitizeRecipients([]string{"user@njupt.edu.cn\r\nBcc: evil@example.com"}); err == nil {
		t.Fatal("sanitizeRecipients() error = nil, want rejection of a CRLF recipient")
	}
}
