package mailer

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// AlumniResult is the outcome of an account-request review, as the applicant is
// told it.
//
// No password field, deliberately: the approved account's generated password is
// discarded at approval time and the applicant sets their own through the reset
// flow, so there is nothing here to leak into a mailbox.
type AlumniResult struct {
	// Name is the applicant's name, for the greeting.
	Name string
	// Approved selects the copy.
	Approved bool
	// Recovered selects the restore-access copy inside the approval branch: the
	// account already existed and a personal email has just been bound to it.
	Recovered bool
	// RejectReason is required when Approved is false: a rejection with no
	// explanation gives the applicant nothing to correct.
	RejectReason string
	// ResetURL is the password-reset page an approved applicant must visit.
	ResetURL string
	// SupportEmail is the appeal channel quoted in a rejection.
	SupportEmail string
}

// SendAlumniRequestResult delivers the verdict for an account-request ticket.
//
// The recipient must be the applicant's personal email, never the login email the
// ticket carries — that address is the deactivated school mailbox.
func (m *Mailer) SendAlumniRequestResult(ctx context.Context, to string, result AlumniResult) error {
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("mailer: recipient is required")
	}
	if !result.Approved && strings.TrimSpace(result.RejectReason) == "" {
		// Refused rather than sent with a blank reason: the reason is the only
		// actionable content a rejection carries.
		return fmt.Errorf("mailer: reject reason is required for a rejection")
	}
	if result.Approved && strings.TrimSpace(result.ResetURL) == "" {
		// An approval whose only instruction is missing is worse than no email: it
		// tells the applicant their account exists and leaves them no way in.
		return fmt.Errorf("mailer: reset url is required for an approval")
	}

	subject, title := alumniResultCopy(result.Approved, result.Recovered)
	data := alumniResultData{
		layoutData: layoutData{
			Subject: subject,
			Title:   title,
			Year:    time.Now().Year(),
		},
		Name:         result.Name,
		Approved:     result.Approved,
		Recovered:    result.Recovered,
		RejectReason: result.RejectReason,
		ResetURL:     result.ResetURL,
		SupportEmail: result.SupportEmail,
	}
	htmlBody, err := renderAlumniResultHTML(data)
	if err != nil {
		return fmt.Errorf("render alumni result html: %w", err)
	}
	return m.send(ctx, []string{to}, subject, renderAlumniResultText(data), htmlBody)
}

// alumniResultCopy returns the subject and the in-mail heading for a verdict.
func alumniResultCopy(approved, recovered bool) (string, string) {
	if approved {
		if recovered {
			return "SAST Link 账号访问方式已恢复", "账号访问方式已恢复"
		}
		return "SAST Link 账号申请已通过", "账号申请已通过"
	}
	return "SAST Link 账号申请未通过", "账号申请未通过"
}
