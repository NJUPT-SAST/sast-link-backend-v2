package sessionworker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/mailer"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
)

type forgotUsers struct {
	users map[string]*model.User
	err   error
}

func (f forgotUsers) FindAuthUserByLoginIdentifier(_ context.Context, identifier string) (*model.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	user, ok := f.users[identifier]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return user, nil
}

type forgotCodes struct {
	email, code, purpose string
	err                  error
	failFirst            bool
	calls                int
}

func (f *forgotCodes) SaveVerificationCode(_ context.Context, purpose, email, code string, _ time.Duration) error {
	f.calls++
	if f.err != nil || (f.failFirst && f.calls == 1) {
		if f.err != nil {
			return f.err
		}
		return errors.New("redis down")
	}
	f.email, f.code, f.purpose = email, code, purpose
	return nil
}

type forgotMailer struct {
	to, code string
	purpose  mailer.VerificationPurpose
	err      error
	sent     chan struct{}
}

func (f *forgotMailer) SendVerificationCode(_ context.Context, to, code string, purpose mailer.VerificationPurpose) error {
	if f.err != nil {
		return f.err
	}
	f.to, f.code, f.purpose = to, code, purpose
	if f.sent != nil {
		f.sent <- struct{}{}
	}
	return nil
}

func TestForgotPasswordProcessesKnownAccount(t *testing.T) {
	codes := &forgotCodes{}
	emailer := &forgotMailer{}
	worker := NewForgotPassword(forgotUsers{users: map[string]*model.User{"user@njupt.edu.cn": {ID: 42}}}, codes, emailer, nil)
	worker.process(context.Background(), session.ForgotPasswordJob{Email: "user@njupt.edu.cn"})
	if codes.email != "user@njupt.edu.cn" || len(codes.code) != 6 || codes.purpose != string(mailer.VerificationPurposeResetPassword) {
		t.Fatalf("saved code = %+v, want reset code for account", codes)
	}
	if emailer.to != codes.email || emailer.code != codes.code || emailer.purpose != mailer.VerificationPurposeResetPassword {
		t.Fatalf("mail = %+v, want saved reset code", emailer)
	}
}

func TestForgotPasswordIgnoresUnknownAccount(t *testing.T) {
	codes := &forgotCodes{}
	emailer := &forgotMailer{}
	worker := NewForgotPassword(forgotUsers{users: map[string]*model.User{}}, codes, emailer, nil)
	worker.process(context.Background(), session.ForgotPasswordJob{Email: "nobody@njupt.edu.cn"})
	if codes.email != "" || emailer.to != "" {
		t.Fatalf("unknown account produced code/mail: %+v %+v", codes, emailer)
	}
}

// A member whose only reachable address is a bound other_mail identity resets
// through that address: the worker resolves the identifier to the account and
// delivers the code where the member can read it.
func TestForgotPasswordResolvesBoundOtherMail(t *testing.T) {
	codes := &forgotCodes{}
	emailer := &forgotMailer{}
	worker := NewForgotPassword(forgotUsers{users: map[string]*model.User{"member@example.com": {ID: 42}}}, codes, emailer, nil)
	worker.process(context.Background(), session.ForgotPasswordJob{Email: "member@example.com"})
	if codes.email != "member@example.com" || len(codes.code) != 6 {
		t.Fatalf("saved code = %+v, want a reset code delivered to the bound address", codes)
	}
	if emailer.to != "member@example.com" {
		t.Fatalf("mail to = %q, want the bound address the member submitted", emailer.to)
	}
}

func TestForgotPasswordDeliveryFailureDoesNotStopWorker(t *testing.T) {
	codes := &forgotCodes{failFirst: true}
	emailer := &forgotMailer{sent: make(chan struct{}, 1)}
	worker := NewForgotPassword(forgotUsers{users: map[string]*model.User{"user@njupt.edu.cn": {ID: 42}}}, codes, emailer, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	if !worker.EnqueueForgotPassword(session.ForgotPasswordJob{Email: "user@njupt.edu.cn"}) {
		t.Fatal("enqueue failed")
	}
	time.Sleep(20 * time.Millisecond)
	if !worker.EnqueueForgotPassword(session.ForgotPasswordJob{Email: "user@njupt.edu.cn"}) {
		t.Fatal("second enqueue failed")
	}
	select {
	case <-emailer.sent:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not process job after failure")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run error = %v", err)
	}
}
