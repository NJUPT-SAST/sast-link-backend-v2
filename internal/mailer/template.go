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
	Digits     []string
	TTLMinutes int
	Year       int
}

// splitDigits splits a verification code into single characters so the HTML
// template can render each digit in its own box.
func splitDigits(code string) []string {
	digits := make([]string, 0, len(code))
	for _, r := range code {
		digits = append(digits, string(r))
	}
	return digits
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

// verificationEmailTemplate mirrors email-preview.html (SAST brown theme,
// dual logos, boxed digits) using table layout and inline styles, which are
// the only constructs reliably supported across mail clients. The <style>
// block only carries a mobile media query as progressive enhancement.
const verificationEmailTemplate = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{.Subject}}</title>
  <style>
    @media (max-width:480px){
      .canvas{padding:24px 12px!important;}
      .brand{padding:24px 24px 0!important;}
      .content{padding:24px 24px 30px!important;}
      .footer{padding:16px 24px!important;}
      .gap{width:7px!important;}
      .digit{width:42px!important;height:50px!important;font-size:24px!important;line-height:50px!important;}
    }
  </style>
</head>
<body style="margin:0;background:#f3f1ec;color:#211e1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',Arial,sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f3f1ec;">
    <tr>
      <td class="canvas" align="center" style="padding:40px 16px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:520px;background:#ffffff;border:1px solid #e6e0d6;">
          <tr>
            <td class="brand" align="center" style="padding:28px 32px;border-bottom:1px solid #f0ebe2;">
              <img src="https://sast.fun/share/logos/logo-black.png" alt="SAST" width="63" height="40" style="display:block;height:40px;width:auto;border:0;">
            </td>
          </tr>
          <tr>
            <td class="content" style="padding:26px 32px 34px;">
              <h1 style="margin:0 0 14px;font-size:22px;line-height:1.35;font-weight:650;letter-spacing:-.025em;color:#211e1a;">{{.Title}}</h1>
              <p style="margin:0;font-size:15px;line-height:1.75;color:#6c655c;">你正在{{.Action}}，请使用下面的验证码。</p>
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:26px 0 22px;">
                <tr>{{range $i, $d := .Digits}}{{if $i}}<td class="gap" width="10" style="width:10px;font-size:0;line-height:0;">&nbsp;</td>{{end}}<td class="digit" width="52" height="58" align="center" valign="middle" style="width:52px;height:58px;background:#f5f0e8;border:1px solid #ddd3c3;color:#5e3d27;font-family:SFMono-Regular,Consolas,'Liberation Mono',monospace;font-size:28px;font-weight:700;line-height:58px;">{{$d}}</td>{{end}}</tr>
              </table>
              <p style="margin:0;font-size:13px;line-height:1.7;color:#6c655c;">验证码在 {{.TTLMinutes}} 分钟内有效。请勿将验证码发给其他人。若非本人操作，可忽略本邮件。</p>
            </td>
          </tr>
          <tr>
            <td class="footer" style="padding:18px 32px;border-top:1px solid #f0ebe2;font-size:12px;line-height:1.6;color:#a39a8c;">© {{.Year}} NJUPT SAST</td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`
