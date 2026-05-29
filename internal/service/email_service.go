package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
)

// EmailService handles sending emails via SMTP.
type EmailService struct {
	cfg *config.SMTPConfig
}

// NewEmailService creates a new EmailService.
func NewEmailService(cfg *config.SMTPConfig) *EmailService {
	return &EmailService{cfg: cfg}
}

// SendVerificationCode sends a verification code email.
func (s *EmailService) SendVerificationCode(to, code string) error {
	subject := "SAST Link 验证码"
	body := fmt.Sprintf(`
<html>
<body>
  <p>您的验证码是：</p>
  <h2>%s</h2>
  <p>验证码 5 分钟内有效，请勿转发给他人。</p>
</body>
</html>`, code)

	return s.send(context.Background(), to, subject, body)
}

func (s *EmailService) send(ctx context.Context, to, subject, htmlBody string) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	msg := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", s.cfg.From, to, subject, htmlBody)

	auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)

	if s.cfg.UseTLS {
		dialer := &tls.Dialer{Config: &tls.Config{ServerName: s.cfg.Host}}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("smtp tls dial: %w", err)
		}
		defer func() { _ = conn.Close() }()

		client, err := smtp.NewClient(conn, s.cfg.Host)
		if err != nil {
			return fmt.Errorf("smtp client: %w", err)
		}
		defer func() { _ = client.Quit() }()

		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
		if err := client.Mail(s.cfg.From); err != nil {
			return fmt.Errorf("smtp mail: %w", err)
		}
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("smtp rcpt: %w", err)
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("smtp data: %w", err)
		}
		_, err = w.Write([]byte(msg))
		if err != nil {
			return fmt.Errorf("smtp write: %w", err)
		}
		return w.Close()
	}

	return smtp.SendMail(addr, auth, s.cfg.From, []string{to}, []byte(msg))
}
