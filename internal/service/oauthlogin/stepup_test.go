package oauthlogin

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

func TestBindRequiresStepUpPassword(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)

	result, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("Bind with correct password: %v", err)
	}
	if result.Identity.UserID != 42 {
		t.Fatalf("bound to user %d, want 42", result.Identity.UserID)
	}
	if doubles.Passwords.calls != 1 {
		t.Fatalf("password verifier calls = %d, want 1", doubles.Passwords.calls)
	}
	if doubles.GitHub.calls != 1 {
		t.Fatalf("provider exchange calls = %d, want 1", doubles.GitHub.calls)
	}
}

func TestBindRejectsMissingPasswordBeforeExchange(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)

	_, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
	if doubles.GitHub.calls != 0 || doubles.Passwords.calls != 0 {
		t.Fatal("empty password must fail before the exchange and the verifier")
	}
}

func TestBindRejectsWrongPasswordAndAudits(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)

	_, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "wrong",
	})
	assertKind(t, err, KindInvalidToken, errcode.CodePasswordInvalid)
	// A wrong password is audited as a failed bind, so an account-takeover
	// attempt leaves the same trail as the email-bind step-up.
	want := fmt.Sprintf("oauth_bind:%d", errcode.CodePasswordInvalid)
	if got := doubles.Audits.failedActions(); len(got) != 1 || got[0] != want {
		t.Fatalf("failed audits = %v, want [%s]", got, want)
	}
	// The provider exchange must not run on a wrong password: the caller's code is
	// single-use and a failed step-up must not spend it.
	if doubles.GitHub.calls != 0 {
		t.Fatal("provider exchange ran on a wrong password")
	}
}

func TestBindStepUpThrottledPerUser(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	limiter := &fakeLimiter{result: LimitResult{Allowed: false, RetryAfter: 30 * time.Second}}
	service.StepUpLimiter = limiter

	_, err := service.Bind(context.Background(), BindInput{
		UserID:   42,
		Provider: model.LoginMethodGitHub,
		Code:     "provider-code",
		Password: "secret",
	})
	assertKind(t, err, KindRateLimited, errcode.CodeRateLimited)
	// Keyed per user, so a campus NAT never shares one budget with other users.
	if len(limiter.calls) != 1 || limiter.calls[0] != "password_step_up:user:42" {
		t.Fatalf("limiter calls = %v, want [password_step_up:user:42]", limiter.calls)
	}
}
