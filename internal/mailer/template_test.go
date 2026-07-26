package mailer

import (
	"os"
	"strings"
	"testing"
)

func testVerificationData() verificationEmailData {
	return verificationEmailData{
		Subject:    "SAST Link 绑定邮箱验证码",
		Title:      "绑定邮箱验证码",
		Action:     "绑定此邮箱到 SAST Link 账号",
		Code:       "377769",
		Digits:     splitDigits("377769"),
		TTLMinutes: 5,
		Year:       2026,
	}
}

func TestSplitDigits(t *testing.T) {
	digits := splitDigits("377769")
	want := []string{"3", "7", "7", "7", "6", "9"}
	if len(digits) != len(want) {
		t.Fatalf("len(digits)=%d, want %d", len(digits), len(want))
	}
	for i := range want {
		if digits[i] != want[i] {
			t.Errorf("digits[%d]=%q, want %q", i, digits[i], want[i])
		}
	}
	if got := splitDigits(""); len(got) != 0 {
		t.Errorf("splitDigits(\"\") has %d digits, want 0", len(got))
	}
}

func TestRenderVerificationText(t *testing.T) {
	got := renderVerificationText(testVerificationData())
	want := "你正在绑定此邮箱到 SAST Link 账号。验证码：377769。5 分钟内有效。"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRenderVerificationHTML(t *testing.T) {
	html, err := renderVerificationHTML(testVerificationData())
	if err != nil {
		t.Fatalf("renderVerificationHTML: %v", err)
	}
	for _, want := range []string{
		"<title>SAST Link 绑定邮箱验证码</title>",
		"绑定邮箱验证码",                // h1 title
		"你正在绑定此邮箱到 SAST Link 账号", // action sentence
		"验证码在 5 分钟内有效",
		"© 2026 NJUPT SAST",
		"https://sast.fun/share/logos/logo-black.png",
		"#f5f0e8", // digit box background
		"#5e3d27", // digit color
		"#f3f1ec", // canvas background
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered html missing %q", want)
		}
	}
	if got := strings.Count(html, `class="digit"`); got != 6 {
		t.Errorf("digit cells=%d, want 6", got)
	}
	// 5 gap cells between 6 digits
	if got := strings.Count(html, `class="gap"`); got != 5 {
		t.Errorf("gap cells=%d, want 5", got)
	}

	// Local visual check: MAIL_PREVIEW_OUT=/tmp/mail.html go test ./internal/mailer/
	if out := os.Getenv("MAIL_PREVIEW_OUT"); out != "" {
		if err := os.WriteFile(out, []byte(html), 0o600); err != nil { //nolint:gosec // Developer-supplied local preview path, opt-in via env var.
			t.Fatalf("write preview: %v", err)
		}
		t.Logf("preview written to %s", out)
	}
}

func TestVerificationCopy(t *testing.T) {
	for _, purpose := range []VerificationPurpose{
		VerificationPurposeRegister,
		VerificationPurposeResetPassword,
		VerificationPurposeBindEmail,
	} {
		subject, title, action, err := verificationCopy(purpose)
		if err != nil {
			t.Errorf("%s: %v", purpose, err)
			continue
		}
		if subject == "" || title == "" || action == "" {
			t.Errorf("%s: empty copy (subject=%q title=%q action=%q)", purpose, subject, title, action)
		}
		if !strings.Contains(subject, title) {
			t.Errorf("%s: title %q is not a suffix-free substring of subject %q", purpose, title, subject)
		}
	}
	if _, _, _, err := verificationCopy("bogus"); err == nil {
		t.Error("verificationCopy(\"bogus\"): want error, got nil")
	}
}
