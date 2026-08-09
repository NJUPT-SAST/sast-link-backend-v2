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
		TTLMinutes: 5,
		Year:       2026,
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
		"https://link.sast.fun/icon.svg",
		"#fafafa",          // --background (light)
		"#0a0a0a",          // --foreground (light)
		"#060606",          // --background (dark)
		"rgba(0,0,0,0.05)", // code box background
		"prefers-color-scheme: dark",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered html missing %q", want)
		}
	}
	// The code is one contiguous text node (letter-spacing is visual only), so
	// copying it yields "377769", not "3 7 7 7 6 9". Assert it appears whole
	// and that the old per-digit box cells are gone.
	if !strings.Contains(html, ">377769</td>") {
		t.Errorf("rendered html: verification code is not a single text node")
	}
	if strings.Contains(html, `class="digit"`) || strings.Contains(html, `class="gap"`) {
		t.Errorf("rendered html still contains per-digit box/gap cells")
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
