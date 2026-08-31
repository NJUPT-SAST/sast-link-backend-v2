package mailer

import (
	"context"
	"strings"
	"testing"
)

func approvedData() alumniResultData {
	return alumniResultData{
		layoutData: layoutData{
			Subject: "SAST Link 账号申请已通过",
			Title:   "账号申请已通过",
			Year:    2026,
		},
		Name:         "张三",
		Approved:     true,
		ResetURL:     "https://link.sast.fun/reset",
		SupportEmail: "link@sast.fun",
	}
}

func rejectedData() alumniResultData {
	return alumniResultData{
		layoutData: layoutData{
			Subject: "SAST Link 账号申请未通过",
			Title:   "账号申请未通过",
			Year:    2026,
		},
		Name:         "张三",
		Approved:     false,
		RejectReason: "学号与姓名不匹配，请核对后重新提交",
		SupportEmail: "link@sast.fun",
	}
}

// The approval copy has to name the personal email, because the obvious choice is
// the wrong one: the account's login email is the deactivated school mailbox that
// caused the application, so a reset code sent there never arrives.
func TestRenderAlumniResultHTMLApproved(t *testing.T) {
	html, err := renderAlumniResultHTML(approvedData())
	if err != nil {
		t.Fatalf("renderAlumniResultHTML: %v", err)
	}
	for _, want := range []string{
		"<title>SAST Link 账号申请已通过</title>",
		"账号申请已通过",
		"张三 你好",
		"个人邮箱",
		"原学号邮箱已无法用于收信",
		"https://link.sast.fun/reset",
		"© 2026 NJUPT SAST",
		// Shared chrome: the layout is the same one the verification email uses.
		"https://link.sast.fun/icon.svg",
		"prefers-color-scheme: dark",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("approved html missing %q", want)
		}
	}
	if strings.Contains(html, "驳回") || strings.Contains(html, "未通过") {
		t.Error("approved html carries rejection copy")
	}
}

func TestRenderAlumniResultHTMLRejected(t *testing.T) {
	html, err := renderAlumniResultHTML(rejectedData())
	if err != nil {
		t.Fatalf("renderAlumniResultHTML: %v", err)
	}
	for _, want := range []string{
		"<title>SAST Link 账号申请未通过</title>",
		"学号与姓名不匹配，请核对后重新提交",
		"可以修正后重新提交",
		"link@sast.fun",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rejected html missing %q", want)
		}
	}
	// A rejection must not carry the reset call to action: there is no account to
	// set a password for.
	if strings.Contains(html, "设置密码") {
		t.Error("rejected html carries the password-reset action")
	}
}

// send() builds a multipart/alternative message, so a missing text part would
// render as an empty email in any client that prefers text.
func TestRenderAlumniResultText(t *testing.T) {
	approved := renderAlumniResultText(approvedData())
	for _, want := range []string{"张三", "已通过", "https://link.sast.fun/reset", "个人邮箱"} {
		if !strings.Contains(approved, want) {
			t.Errorf("approved text missing %q", want)
		}
	}

	rejected := renderAlumniResultText(rejectedData())
	for _, want := range []string{"张三", "未通过", "学号与姓名不匹配，请核对后重新提交", "link@sast.fun"} {
		if !strings.Contains(rejected, want) {
			t.Errorf("rejected text missing %q", want)
		}
	}
}

// The password is generated, hashed and discarded at approval time. This asserts
// the rendered output cannot carry one — the struct has no such field, and this is
// what fails if someone adds one and wires it into the template.
func TestAlumniResultNeverRendersACredential(t *testing.T) {
	for _, data := range []alumniResultData{approvedData(), rejectedData()} {
		html, err := renderAlumniResultHTML(data)
		if err != nil {
			t.Fatalf("renderAlumniResultHTML: %v", err)
		}
		text := renderAlumniResultText(data)
		for _, forbidden := range []string{"密码：", "初始密码", "password"} {
			if strings.Contains(html, forbidden) {
				t.Errorf("html mentions %q", forbidden)
			}
			if strings.Contains(text, forbidden) {
				t.Errorf("text mentions %q", forbidden)
			}
		}
	}
}

// Recovered is only meaningful on an approval: a rejection carrying it would
// render the restore-access copy with an empty reset link.
func TestSendAlumniRequestResultRefusesRecoveredRejection(t *testing.T) {
	mailer := New(Config{Host: "smtp.test", Port: 587, From: "link@sast.fun"})
	err := mailer.SendAlumniRequestResult(context.Background(), "alumni@example.com",
		AlumniResult{Approved: false, Recovered: true, RejectReason: "请补充资料"})
	if err == nil || !strings.Contains(err.Error(), "only valid for an approval") {
		t.Fatalf("error = %v, want the recovered/rejected pairing refused", err)
	}
}
