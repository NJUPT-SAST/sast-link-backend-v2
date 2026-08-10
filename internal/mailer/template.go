package mailer

import (
	"bytes"
	"fmt"
	"html/template"
)

type verificationEmailData struct {
	Subject    string
	Title      string
	Action     string
	Code       string
	TTLMinutes int
	Year       int
}

func renderVerificationText(data verificationEmailData) string {
	return fmt.Sprintf("你正在%s。验证码：%s。%d 分钟内有效。", data.Action, data.Code, data.TTLMinutes)
}

// verificationTemplate is parsed once at startup; the template is static, and
// re-parsing it per email would throw away the compile on every send.
var verificationTemplate = template.Must(template.New("verification").Parse(verificationEmailTemplate))

func renderVerificationHTML(data verificationEmailData) (string, error) {
	var buf bytes.Buffer
	if err := verificationTemplate.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute verification template: %w", err)
	}
	return buf.String(), nil
}

// verificationEmailTemplate mirrors the sast-link-next frontend design system
// (app/globals.css): the monochrome tokens are used verbatim — --background
// #fafafa, --foreground #0a0a0a, --muted-foreground rgba(0,0,0,0.55),
// --border rgba(0,0,0,0.18), --input rgba(0,0,0,0.3), --starfield #404040 —
// with sharp corners and no shadows. The verification code is one contiguous
// text node with letter-spacing, so copying it yields "386291" rather than
// digit-box cells that paste as "3 8 6 2 9 1". Dark mode is progressive
// enhancement via prefers-color-scheme; clients without it fall back to the
// inline light styles. Table layout and inline styles are the only constructs
// reliably supported across mail clients; the <style> block only carries the
// mobile query and the dark overrides.
const verificationEmailTemplate = `<!doctype html>
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
    }
    @media (prefers-color-scheme: dark){
      .mail-body{background-color:#060606!important;}
      .starfield{background-image:radial-gradient(circle,rgba(255,255,255,0.18) 1px,transparent 1.4px)!important;}
      .card{background:#0c0c0c!important;border-color:rgba(255,255,255,0.18)!important;}
      .hairline{border-color:rgba(255,255,255,0.18)!important;}
      .text-main{color:#ffffff!important;}
      .text-muted{color:rgba(255,255,255,0.55)!important;}
      .codebox{background:rgba(255,255,255,0.06)!important;border-color:rgba(255,255,255,0.18)!important;color:#ffffff!important;}
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
