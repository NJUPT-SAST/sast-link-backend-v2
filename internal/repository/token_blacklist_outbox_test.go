package repository

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A provider or driver can hand back bytes that are not valid UTF-8 at all; the
// truncation must replace them rather than stop at the first invalid byte,
// which on a garbage-heavy payload would drop nearly the whole message.
func TestTruncateOutboxDeliveryErrorReplacesInvalidUTF8(t *testing.T) {
	raw := "delivery failed: \xff\xfe" + strings.Repeat("错", 400)

	got := truncateOutboxDeliveryError(raw)

	if !utf8.ValidString(got) {
		t.Fatalf("truncated error is not valid UTF-8: %q", got[:32])
	}
	if len(got) > maxOutboxDeliveryErrorLength {
		t.Fatalf("truncated length = %d, want <= %d", len(got), maxOutboxDeliveryErrorLength)
	}
	if !strings.HasPrefix(got, "delivery failed: ") {
		t.Fatalf("truncated error = %q, want the valid prefix to survive", got[:32])
	}
}

// An input already inside the budget survives byte for byte.
func TestTruncateOutboxDeliveryErrorKeepsShortInput(t *testing.T) {
	if got := truncateOutboxDeliveryError(" connection reset "); got != "connection reset" {
		t.Fatalf("truncateOutboxDeliveryError() = %q, want the trimmed input", got)
	}
}
