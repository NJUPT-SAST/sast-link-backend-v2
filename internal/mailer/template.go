package mailer

import (
	"bytes"
	"fmt"
	"html/template"
)

// layoutData is the chrome every email shares.
//
// Embedded by each email's own data struct rather than passed alongside it, so a
// template always receives one value and the layout can read Subject/Title/Year
// off whatever concrete type is executing.
type layoutData struct {
	Subject string
	Title   string
	Year    int
}

type verificationEmailData struct {
	layoutData
	Action     string
	Code       string
	TTLMinutes int
}

// alumniResultData is the account-request verdict email.
//
// No password field, deliberately: the approved account's initial password is
// generated, hashed and discarded at approval time, so "we never mail a
// password" is a property of the type rather than a habit of the caller.
type alumniResultData struct {
	layoutData
	Name string
	// Approved selects the copy. Both outcomes are mailed: a rejection with no
	// notification leaves the applicant waiting for something that already happened.
	Approved bool
	// Recovered selects the restore-access wording inside the approval branch:
	// the account existed all along, a personal email has just been bound to it.
	Recovered bool
	// RejectReason is what the applicant has to correct before resubmitting. Only
	// read when Approved is false.
	RejectReason string
	// ResetURL is where an approved applicant sets their password. They must enter
	// their personal email there, not the school address that became their login
	// identity, because the school mailbox is the one that stopped working.
	ResetURL string
	// SupportEmail is the appeal channel for a rejection.
	SupportEmail string
}

// Templates are parsed once at startup. The layout is parsed first and each
// email's content block is added to its own clone, so the two cannot see each
// other's blocks and a missing content definition fails here rather than
// rendering an empty body.
var (
	verificationTemplate = mustComposeTemplate("verification", verificationContentTemplate)
	alumniResultTemplate = mustComposeTemplate("alumni_result", alumniResultContentTemplate)
)

// mustComposeTemplate builds one email from the shared layout plus its content
// block.
func mustComposeTemplate(name, content string) *template.Template {
	return template.Must(template.Must(template.New(name).Parse(layoutTemplate)).Parse(content))
}

func renderVerificationText(data verificationEmailData) string {
	return fmt.Sprintf("你正在%s。验证码：%s。%d 分钟内有效。", data.Action, data.Code, data.TTLMinutes)
}

func renderVerificationHTML(data verificationEmailData) (string, error) {
	return renderTemplate(verificationTemplate, data, "verification")
}

// renderAlumniResultText is the plain-text alternative. Not optional: send()
// builds a multipart/alternative message and a client that prefers text would
// otherwise receive an empty part.
func renderAlumniResultText(data alumniResultData) string {
	if data.Approved && data.Recovered {
		return fmt.Sprintf(
			"%s 你好，你的账号访问方式已恢复：你的个人邮箱已绑定到学号对应的 SAST Link 账号。\n\n"+
				"请访问 %s 设置新密码。填写邮箱时请使用你在申请中填写的个人邮箱，"+
				"原学号邮箱已无法用于收信。\n\n设置完成后即可登录。",
			data.Name, data.ResetURL)
	}
	if data.Approved {
		return fmt.Sprintf(
			"%s 你好，你的 SAST Link 账号申请已通过，账号已开通。\n\n"+
				"请访问 %s 设置密码。填写邮箱时请使用你在申请中填写的个人邮箱，"+
				"原学号邮箱已无法用于收信。\n\n设置完成后即可登录。",
			data.Name, data.ResetURL)
	}
	return fmt.Sprintf(
		"%s 你好，你的 SAST Link 账号申请未通过。\n\n原因：%s\n\n"+
			"你可以修正后重新提交申请。如有疑问，请联系 %s。",
		data.Name, data.RejectReason, data.SupportEmail)
}

func renderAlumniResultHTML(data alumniResultData) (string, error) {
	return renderTemplate(alumniResultTemplate, data, "alumni result")
}

func renderTemplate(tmpl *template.Template, data any, label string) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute %s template: %w", label, err)
	}
	return buf.String(), nil
}

// layoutTemplate mirrors the sast-link-next frontend design system
// (app/globals.css): the monochrome tokens are used verbatim — --background
// #fafafa, --foreground #0a0a0a, --muted-foreground rgba(0,0,0,0.55),
// --border rgba(0,0,0,0.18), --input rgba(0,0,0,0.3), --starfield #404040 —
// with sharp corners and no shadows. Dark mode is progressive enhancement via
// prefers-color-scheme; clients without it fall back to the inline light
// styles. Table layout and inline styles are the only constructs reliably
// supported across mail clients; the <style> block only carries the mobile
// query and the dark overrides.
//
// Shared by every email so the chrome cannot drift between them. Each email
// supplies a "content" block, which renders inside the card below the heading.
const layoutTemplate = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{.Subject}}</title>
  <style>
    @media (max-width:480px){
      .canvas{padding:16px 8px!important;}
      .brand{padding:22px 20px 22px!important;}
      .content{padding:24px 20px 28px!important;}
      .footer{padding:16px 20px!important;}
      .codebox{padding:16px 20px!important;font-size:26px!important;letter-spacing:6px!important;}
      /* display:block makes the td block-level, which voids the HTML align
         attribute; text-align keeps the button label centered on small screens. */
      .actionbtn{display:block!important;text-align:center!important;}
    }
    @media (prefers-color-scheme: dark){
      .mail-body{background-color:#060606!important;}
      .starfield{background-image:radial-gradient(circle,rgba(255,255,255,0.18) 1px,transparent 1.4px)!important;}
      .card{background:#0c0c0c!important;border-color:rgba(255,255,255,0.18)!important;}
      .hairline{border-color:rgba(255,255,255,0.18)!important;}
      .text-main{color:#ffffff!important;}
      .text-muted{color:rgba(255,255,255,0.55)!important;}
      .codebox{background:rgba(255,255,255,0.06)!important;border-color:rgba(255,255,255,0.18)!important;color:#ffffff!important;}
      /* The button text lives in an <a> with inline color:#ffffff, which would
         otherwise stay white on the lightened button. The td's own color is
         useless (no text node), so the link is targeted directly. */
      .actionbtn{background:#ffffff!important;border-color:#ffffff!important;}
      .actionbtn a{color:#0a0a0a!important;}
      .footer{color:rgba(255,255,255,0.4)!important;}
      .logo-light{display:none!important;}
      .logo-dark{display:block!important;}
    }
  </style>
</head>
<body style="margin:0;background:#fafafa;color:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',Arial,sans-serif;">
  <table class="mail-body starfield" role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#fafafa;background-image:radial-gradient(circle,rgba(64,64,64,0.20) 1px,transparent 1.4px);background-size:22px 22px;">
    <tr>
      <td class="canvas" align="center" style="padding:48px 16px;">
        <table class="card" role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:520px;background:#ffffff;border:1px solid rgba(0,0,0,0.18);">
          <tr>
            <td class="brand" align="center" style="padding:26px 32px 26px;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td align="right" valign="middle" style="padding-right:12px;">
                    <img class="logo-light" src="https://link.sast.fun/icon.svg" alt="" width="34" height="34" style="display:block;height:34px;width:34px;border:0;">
                    <img class="logo-dark" src="https://link.sast.fun/icon.svg" alt="" width="34" height="34" style="display:none;height:34px;width:34px;border:0;filter:invert(1) brightness(2);">
                  </td>
                  <td align="left" valign="middle">
                    <span class="text-main" style="font-size:20px;font-weight:700;letter-spacing:-0.02em;color:#0a0a0a;">SAST Link</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td class="content hairline" style="padding:24px 40px 34px;border-top:1px solid rgba(0,0,0,0.18);">
              <h1 class="text-main" style="margin:0 0 12px;font-size:24px;line-height:1.3;font-weight:650;letter-spacing:-0.025em;color:#0a0a0a;">{{.Title}}</h1>
{{template "content" .}}
            </td>
          </tr>
          <tr>
            <td class="footer hairline" style="padding:18px 40px;border-top:1px solid rgba(0,0,0,0.18);font:500 11px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;letter-spacing:0.06em;color:rgba(0,0,0,0.4);">© {{.Year}} NJUPT SAST</td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`

// verificationContentTemplate is the code block. The code is one contiguous text
// node with letter-spacing, so copying it yields "386291" rather than digit-box
// cells that paste as "3 8 6 2 9 1".
const verificationContentTemplate = `{{define "content"}}
              <p class="text-muted" style="margin:0;font-size:15px;line-height:1.75;color:rgba(0,0,0,0.55);">你正在{{.Action}}，请使用下面的验证码完成验证。</p>
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="margin:26px 0 24px;">
                <tr>
                  <td align="center">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="width:100%;">
                      <tr>
                        <td class="codebox" align="center" valign="middle" style="background:rgba(0,0,0,0.05);border:1px solid rgba(0,0,0,0.18);color:#0a0a0a;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;font-size:30px;font-weight:600;letter-spacing:8px;line-height:1.2;padding:20px 24px;">{{.Code}}</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
              <p class="text-muted" style="margin:0;font-size:13px;line-height:1.7;color:rgba(0,0,0,0.55);">验证码在 {{.TTLMinutes}} 分钟内有效。请勿将验证码发给其他人。若非本人操作，可忽略本邮件。</p>
{{end}}`

// alumniResultContentTemplate carries both verdicts; the approval branch splits
// again on Recovered for restore-access wording.
//
// The approval copy states which address to use on the reset page, because the
// login email is the deactivated school mailbox — the reset code has to go to
// the personal address instead.
const alumniResultContentTemplate = `{{define "content"}}
{{- if .Recovered}}
              <p class="text-muted" style="margin:0 0 14px;font-size:15px;line-height:1.75;color:rgba(0,0,0,0.55);">{{.Name}} 你好，你的账号访问方式已恢复：你的个人邮箱已绑定到学号对应的 SAST Link 账号。</p>
              <p class="text-muted" style="margin:0;font-size:15px;line-height:1.75;color:rgba(0,0,0,0.55);">请点击下面的按钮设置登录密码。填写邮箱时请使用你在申请中填写的<strong class="text-main" style="color:#0a0a0a;">个人邮箱</strong>，原学号邮箱已无法用于收信。</p>
{{- else if .Approved}}
              <p class="text-muted" style="margin:0 0 14px;font-size:15px;line-height:1.75;color:rgba(0,0,0,0.55);">{{.Name}} 你好，你的 SAST Link 账号申请已通过，账号已开通。</p>
              <p class="text-muted" style="margin:0;font-size:15px;line-height:1.75;color:rgba(0,0,0,0.55);">请点击下面的按钮设置登录密码。填写邮箱时请使用你在申请中填写的<strong class="text-main" style="color:#0a0a0a;">个人邮箱</strong>，原学号邮箱已无法用于收信。</p>
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:26px 0 24px;">
                <tr>
                  <td class="actionbtn" align="center" valign="middle" style="background:#0a0a0a;border:1px solid #0a0a0a;">
                    <a href="{{.ResetURL}}" style="display:inline-block;padding:13px 28px;font-size:15px;font-weight:600;line-height:1.2;color:#ffffff;text-decoration:none;">设置密码</a>
                  </td>
                </tr>
              </table>
              <p class="text-muted" style="margin:0;font-size:13px;line-height:1.7;color:rgba(0,0,0,0.55);">若按钮无法点击，请复制此链接到浏览器打开：{{.ResetURL}}</p>
{{- else}}
              <p class="text-muted" style="margin:0 0 14px;font-size:15px;line-height:1.75;color:rgba(0,0,0,0.55);">{{.Name}} 你好，你的 SAST Link 账号申请未通过。</p>
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="margin:22px 0;">
                <tr>
                  <td class="codebox" align="left" valign="middle" style="background:rgba(0,0,0,0.05);border:1px solid rgba(0,0,0,0.18);color:#0a0a0a;font-size:14px;line-height:1.7;padding:16px 20px;">{{.RejectReason}}</td>
                </tr>
              </table>
              <p class="text-muted" style="margin:0;font-size:13px;line-height:1.7;color:rgba(0,0,0,0.55);">你可以修正后重新提交申请。如有疑问，请联系 {{.SupportEmail}}。</p>
{{- end}}
{{end}}`
