// Package mailer provides a minimal SMTP email sender with styled HTML templates.
package mailer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"regexp"
	"strings"
	"time"
)

// Config holds SMTP connection settings.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	UseTLS   bool
	// MaxConcurrent caps simultaneous SMTP sends. Each send dials a fresh TCP
	// connection and performs a TLS handshake, so an unbounded burst (e.g. a
	// verification-code storm) exhausts file descriptors and SMTP server
	// connections. Requests beyond the cap queue until a slot frees.
	// Non-positive values keep the previous unbounded behavior.
	MaxConcurrent int
}

// Mailer sends email via SMTP.
type Mailer struct {
	cfg Config
	sem chan struct{}
}

// New returns a Mailer from config.
func New(cfg Config) *Mailer {
	m := &Mailer{cfg: cfg}
	if cfg.MaxConcurrent > 0 {
		m.sem = make(chan struct{}, cfg.MaxConcurrent)
	}
	return m
}

// VerificationPurpose identifies the user action an email code authorizes.
type VerificationPurpose string

const (
	VerificationPurposeRegister      VerificationPurpose = "register"
	VerificationPurposeResetPassword VerificationPurpose = "reset_password"
	VerificationPurposeBindEmail     VerificationPurpose = "bind_email"
)

// SendVerificationCode delivers a styled verification-code email.
func (m *Mailer) SendVerificationCode(ctx context.Context, to, code string, purpose VerificationPurpose) error {
	if to == "" || code == "" {
		return fmt.Errorf("mailer: recipient and code are required")
	}
	subject, title, action, err := verificationCopy(purpose)
	if err != nil {
		return err
	}
	data := verificationEmailData{
		Subject:    subject,
		Title:      title,
		Action:     action,
		Code:       code,
		Digits:     splitDigits(code),
		TTLMinutes: 5,
		Year:       time.Now().Year(),
	}
	htmlBody, err := renderVerificationHTML(data)
	if err != nil {
		return fmt.Errorf("render verification html: %w", err)
	}
	textBody := renderVerificationText(data)
	return m.send(ctx, []string{to}, subject, textBody, htmlBody)
}

// verificationCopy returns the email subject, the in-mail heading (subject
// without the "SAST Link " prefix), and the action phrase for a purpose.
func verificationCopy(purpose VerificationPurpose) (string, string, string, error) {
	switch purpose {
	case VerificationPurposeRegister:
		return "SAST Link 注册验证码", "注册验证码", "注册 SAST Link 账号", nil
	case VerificationPurposeResetPassword:
		return "SAST Link 重置密码验证码", "重置密码验证码", "重置 SAST Link 账号密码", nil
	case VerificationPurposeBindEmail:
		return "SAST Link 绑定邮箱验证码", "绑定邮箱验证码", "绑定此邮箱到 SAST Link 账号", nil
	default:
		return "", "", "", fmt.Errorf("mailer: unsupported verification purpose %q", purpose)
	}
}

// Send delivers a plain-text email to the given recipients. Prefer
// SendVerificationCode for verification-code emails so the styled template is used.
func (m *Mailer) Send(ctx context.Context, to []string, subject, body string) error {
	return m.send(ctx, to, subject, body, "")
}

func (m *Mailer) send(ctx context.Context, to []string, subject, textBody, htmlBody string) error {
	if m.cfg.Host == "" || m.cfg.Port == 0 || m.cfg.From == "" {
		return fmt.Errorf("mailer: invalid SMTP configuration")
	}
	if len(to) == 0 {
		return fmt.Errorf("mailer: no recipients")
	}
	if m.sem != nil {
		select {
		case m.sem <- struct{}{}:
			defer func() { <-m.sem }()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	recipients, err := sanitizeRecipients(to)
	if err != nil {
		return err
	}
	from, err := sanitizeAddress(m.cfg.From)
	if err != nil {
		return fmt.Errorf("mailer: invalid From address: %w", err)
	}

	msg, err := buildMessage(from, recipients, subject, textBody, htmlBody)
	if err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)

	if m.cfg.UseTLS {
		return sendTLS(ctx, addr, m.cfg.Host, auth, from, recipients, msg)
	}
	return sendSTARTTLS(ctx, addr, auth, from, recipients, msg)
}

// sanitizeRecipients validates every recipient and returns the canonical
// addr-spec forms. Message headers are assembled by string concatenation, so
// recipients must be proven free of header-breaking characters here rather
// than trusted to be pre-validated by callers.
func sanitizeRecipients(to []string) ([]string, error) {
	sanitized := make([]string, 0, len(to))
	for _, recipient := range to {
		address, err := sanitizeAddress(recipient)
		if err != nil {
			return nil, fmt.Errorf("mailer: invalid recipient: %w", err)
		}
		sanitized = append(sanitized, address)
	}
	return sanitized, nil
}

// addressPattern accepts a conservative addr-spec: printable ASCII atext
// without whitespace, control characters, angle brackets or commas, one @,
// and a dotted domain.
var addressPattern = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)

// sanitizeAddress parses value as a single RFC 5322 address and re-validates
// the extracted addr-spec against a conservative pattern, so the returned
// string is safe to embed in raw message headers.
func sanitizeAddress(value string) (string, error) {
	parsed, err := mail.ParseAddress(strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("parse address: %w", err)
	}
	if !addressPattern.MatchString(parsed.Address) {
		return "", fmt.Errorf("address %q contains unsupported characters", parsed.Address)
	}
	return parsed.Address, nil
}

func buildMessage(from string, to []string, subject, textBody, htmlBody string) ([]byte, error) {
	boundary, err := generateBoundary()
	if err != nil {
		return nil, fmt.Errorf("generate mime boundary: %w", err)
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprint(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprint(&b, "Auto-Submitted: auto-generated\r\n")
	if htmlBody != "" {
		fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary)
		fmt.Fprint(&b, "\r\n")
		writer := multipart.NewWriter(&b)
		if err := writer.SetBoundary(boundary); err != nil {
			return nil, fmt.Errorf("set MIME boundary: %w", err)
		}
		if err := writePart(writer, "text/plain; charset=utf-8", textBody); err != nil {
			return nil, err
		}
		if err := writePart(writer, "text/html; charset=utf-8", htmlBody); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("close MIME writer: %w", err)
		}
	} else {
		fmt.Fprint(&b, "Content-Type: text/plain; charset=utf-8\r\n")
		fmt.Fprint(&b, "Content-Transfer-Encoding: quoted-printable\r\n")
		fmt.Fprint(&b, "\r\n")
		encoded := quotedprintable.NewWriter(&b)
		if _, err := encoded.Write([]byte(textBody)); err != nil {
			return nil, fmt.Errorf("encode text body: %w", err)
		}
		if err := encoded.Close(); err != nil {
			return nil, fmt.Errorf("close text encoder: %w", err)
		}
	}
	return b.Bytes(), nil
}

func writePart(writer *multipart.Writer, contentType, body string) error {
	header := make(textproto.MIMEHeader)
	header.Set("Content-Type", contentType)
	header.Set("Content-Transfer-Encoding", "quoted-printable")
	part, err := writer.CreatePart(header)
	if err != nil {
		return fmt.Errorf("create MIME part: %w", err)
	}
	encoded := quotedprintable.NewWriter(part)
	if _, err := encoded.Write([]byte(body)); err != nil {
		return fmt.Errorf("encode MIME part: %w", err)
	}
	if err := encoded.Close(); err != nil {
		return fmt.Errorf("close MIME part encoder: %w", err)
	}
	return nil
}

func generateBoundary() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return "sastlink_" + hex.EncodeToString(buf[:]), nil
}

func sendSTARTTLS(ctx context.Context, addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		//codeql[go/email-injection] recipient validated by sanitizeAddress; subject/body encoded
		ch <- result{err: smtp.SendMail(addr, auth, from, to, msg)}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return fmt.Errorf("send STARTTLS mail: %w", r.err)
		}
		return nil
	}
}

func sendTLS(ctx context.Context, addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		ch <- result{err: doSendTLS(ctx, addr, host, auth, from, to, msg)}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return fmt.Errorf("send TLS mail: %w", r.err)
		}
		return nil
	}
}

func doSendTLS(ctx context.Context, addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	plainConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		slog.Error("smtp dial failed", "addr", addr, "error", err)
		return fmt.Errorf("dial: %w", err)
	}
	slog.Debug("smtp dialed", "remote", plainConn.RemoteAddr().String(), "local", plainConn.LocalAddr().String())
	defer plainConn.Close()

	tlsConn := tls.Client(plainConn, &tls.Config{ServerName: host})
	if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
		slog.Error("smtp TLS handshake failed", "host", host, "error", hsErr)
		return fmt.Errorf("TLS handshake: %w", hsErr)
	}
	slog.Debug("smtp TLS ok", "peer", tlsConn.RemoteAddr().String())
	defer tlsConn.Close()

	client, err := smtp.NewClient(tlsConn, host)
	if err != nil {
		slog.Error("smtp NewClient failed", "error", err)
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	if auth != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if authErr := client.Auth(auth); authErr != nil {
				slog.Error("smtp AUTH failed", "user", from, "error", authErr)
				return fmt.Errorf("smtp auth: %w", authErr)
			}
			slog.Debug("smtp AUTH ok", "user", from)
		} else {
			slog.Warn("smtp server did not advertise AUTH extension")
		}
	}

	if mailErr := client.Mail(from); mailErr != nil {
		slog.Error("smtp MAIL FROM failed", "from", from, "error", mailErr)
		return fmt.Errorf("smtp mail from: %w", mailErr)
	}
	slog.Debug("smtp MAIL FROM ok", "from", from)
	for _, rcpt := range to {
		if rcptErr := client.Rcpt(rcpt); rcptErr != nil {
			slog.Error("smtp RCPT TO failed", "rcpt", rcpt, "error", rcptErr)
			return fmt.Errorf("smtp rcpt to %q: %w", rcpt, rcptErr)
		}
		slog.Debug("smtp RCPT TO ok", "rcpt", rcpt)
	}

	w, err := client.Data()
	if err != nil {
		slog.Error("smtp DATA failed", "error", err)
		return fmt.Errorf("smtp data: %w", err)
	}
	// CodeQL reports go/email-injection here because it cannot follow what
	// buildMessage does to its inputs. Recipients are validated by
	// sanitizeRecipients before reaching buildMessage, the subject is Q-encoded,
	// and bodies are quoted-printable inside a MIME part whose boundary is random
	// per message. See TestBuildMessageKeepsInjectedHeadersOutOfTheHeaderBlock and
	// TestBuildMessageBodyCannotForgeMimeBoundary, which fail if any of that
	// changes. The alert is dismissed in the repository's code-scanning settings;
	// CodeQL has no in-source suppression syntax for default setup.
	if _, writeErr := w.Write(msg); writeErr != nil {
		// Close releases the DATA writer so the connection can be torn down; its
		// error is deliberately dropped because writeErr is the failure worth
		// reporting and closing after a failed write is expected to fail too.
		_ = w.Close()
		slog.Error("smtp write body failed", "error", writeErr)
		return fmt.Errorf("smtp write: %w", writeErr)
	}
	if closeErr := w.Close(); closeErr != nil {
		slog.Error("smtp DATA close failed", "error", closeErr)
		return fmt.Errorf("smtp close data: %w", closeErr)
	}
	slog.Debug("smtp DATA close ok, message accepted by server")
	if quitErr := client.Quit(); quitErr != nil {
		slog.Warn("smtp QUIT returned error (message already accepted)", "error", quitErr)
	}
	return nil
}
