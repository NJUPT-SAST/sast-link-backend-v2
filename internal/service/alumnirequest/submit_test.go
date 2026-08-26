package alumnirequest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/turnstile"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func TestSubmitStoresAPendingTicket(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{}
	users := &fakeUsers{}
	audit := &fakeAudit{}
	service := newService(requests, users, audit, &fakeCaptcha{})

	result, err := service.Submit(context.Background(), validSubmit())
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if result.RequestID != 7 {
		t.Fatalf("RequestID = %d, want 7", result.RequestID)
	}
	if requests.created.Status != model.AlumniRequestStatusPending {
		t.Fatalf("status = %s, want pending", requests.created.Status)
	}
	// Emails are lowercased on the way in so the occupancy checks and the eventual
	// unique indexes compare the same bytes the login flow will.
	if requests.created.LoginEmail != "b20040101@njupt.edu.cn" {
		t.Fatalf("login email = %q, want it lowercased", requests.created.LoginEmail)
	}
	// The submitter's address is stored for abuse tracing even though it is never
	// returned on a read.
	if requests.created.ClientIP != "203.0.113.7" {
		t.Fatalf("client ip = %q, want it recorded", requests.created.ClientIP)
	}
}

// major is mandatory here and optional on the console path. A ticket with a blank
// major provisions an account that V010's generated column immediately flags, and
// the applicant is sent to a completion page for a field nobody asked them for.
func TestSubmitRequiresMajor(t *testing.T) {
	t.Parallel()

	input := validSubmit()
	input.Major = "   "
	service := newService(&fakeRequests{}, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

	_, err := service.Submit(context.Background(), input)
	if err == nil {
		t.Fatal("Submit() with a blank major error = nil, want a refusal")
	}
	assertInvalidInput(t, err, "major")
}

// name == student_id is the previous database's placeholder for a missing name and
// the second shape V010 treats as debris. The comparison is delegated to
// validate.IncompleteProfileFields, so this also guards that the delegation stayed
// wired.
func TestSubmitRejectsNameEqualToStudentID(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"B20040101", "b20040101", "  B20040101  "} {
		input := validSubmit()
		input.Name = name
		service := newService(&fakeRequests{}, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

		_, err := service.Submit(context.Background(), input)
		if err == nil {
			t.Fatalf("Submit(name=%q) error = nil, want a refusal", name)
		}
		assertInvalidInput(t, err, "student_id")
	}
}

func TestSubmitRejectsBadEmails(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		mutate   func(*SubmitInput)
		contains string
	}{
		{
			name:     "login email outside the allow-list",
			mutate:   func(in *SubmitInput) { in.LoginEmail = "someone@gmail.com" },
			contains: "login_email",
		},
		{
			name:     "malformed personal email",
			mutate:   func(in *SubmitInput) { in.PersonalEmail = "not-an-email" },
			contains: "personal_email",
		},
		{
			name: "personal email equal to login email",
			mutate: func(in *SubmitInput) {
				in.PersonalEmail = in.LoginEmail
			},
			contains: "personal_email",
		},
		{
			name:     "header injection in the personal email",
			mutate:   func(in *SubmitInput) { in.PersonalEmail = "a@b.com\r\nBcc: victim@c.com" },
			contains: "personal_email",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			input := validSubmit()
			testCase.mutate(&input)
			service := newService(&fakeRequests{}, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

			_, err := service.Submit(context.Background(), input)
			if err == nil {
				t.Fatal("Submit() error = nil, want a refusal")
			}
			assertInvalidInput(t, err, testCase.contains)
		})
	}
}

// Structured numeric fields must refuse free text: a join_year of "abc" would
// otherwise surface in the directory as-is (audit finding #20).
func TestSubmitRejectsNonNumericStructuredFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		mutate   func(*SubmitInput)
		contains string
	}{
		{name: "join_year free text", mutate: func(in *SubmitInput) { in.JoinYear = "abc" }, contains: "join_year"},
		{name: "phone_number free text", mutate: func(in *SubmitInput) { in.PhoneNumber = "not-a-phone" }, contains: "phone_number"},
		{name: "qq_number free text", mutate: func(in *SubmitInput) { in.QQNumber = "abc" }, contains: "qq_number"},
		{name: "phone_number separators only", mutate: func(in *SubmitInput) { in.PhoneNumber = "+- " }, contains: "phone_number"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			input := validSubmit()
			testCase.mutate(&input)
			service := newService(&fakeRequests{}, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

			_, err := service.Submit(context.Background(), input)
			if err == nil {
				t.Fatal("Submit() error = nil, want a refusal")
			}
			assertInvalidInput(t, err, testCase.contains)
		})
	}
}

// Field validation runs before the captcha because a Turnstile token is
// single-use: verifying first would burn it on a submission that then fails a
// length check, and the applicant would have to solve the challenge again to fix a
// typo.
func TestSubmitValidatesFieldsBeforeSpendingTheCaptchaToken(t *testing.T) {
	t.Parallel()

	input := validSubmit()
	input.Major = ""
	captcha := &fakeCaptcha{}
	service := newService(&fakeRequests{}, &fakeUsers{}, &fakeAudit{}, captcha)

	if _, err := service.Submit(context.Background(), input); err == nil {
		t.Fatal("Submit() error = nil, want a refusal")
	}
	if len(captcha.tokens) != 0 {
		t.Fatalf("captcha consulted %d times, want 0 for a field-level refusal", len(captcha.tokens))
	}
}

// The occupancy queries answer "does this email or student ID already exist",
// which is the real disclosure surface. They must sit behind the captcha so an
// unverified caller cannot use the endpoint as an account oracle.
func TestSubmitChecksOccupancyOnlyAfterTheCaptcha(t *testing.T) {
	t.Parallel()

	users := &fakeUsers{}
	captcha := &fakeCaptcha{err: errors.New("bad token")}
	service := newService(&fakeRequests{}, users, &fakeAudit{}, captcha)

	if _, err := service.Submit(context.Background(), validSubmit()); err == nil {
		t.Fatal("Submit() error = nil, want a captcha refusal")
	}
	if len(users.emailQueries) != 0 {
		t.Fatalf("occupancy queried %v, want none before the captcha passes", users.emailQueries)
	}
}

// A rejected token and an unavailable verifier are opposite instructions to the
// caller, so they must not collapse into one code: 40021 says "solve it again",
// 50301 says "nothing you do will help".
func TestSubmitSeparatesCaptchaFailureFromOutage(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		err      error
		wantCode int
		wantKind Kind
	}{
		{
			name:     "rejected token",
			err:      turnstile.ErrFailed,
			wantCode: errcode.CodeCaptchaFailed,
			wantKind: KindCaptchaFailed,
		},
		{
			name:     "verifier unavailable",
			err:      turnstile.ErrUnavailable,
			wantCode: errcode.CodeAlumniRequestUnavailable,
			wantKind: KindUnavailable,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			service := newService(&fakeRequests{}, &fakeUsers{}, &fakeAudit{},
				&fakeCaptcha{err: testCase.err})

			_, err := service.Submit(context.Background(), validSubmit())
			var typed *Error
			if !errors.As(err, &typed) {
				t.Fatalf("Submit() error = %v, want a typed error", err)
			}
			if typed.Kind != testCase.wantKind || typed.Code != testCase.wantCode {
				t.Fatalf("kind/code = %s/%d, want %s/%d",
					typed.Kind, typed.Code, testCase.wantKind, testCase.wantCode)
			}
		})
	}
}

// A nil verifier is a wiring mistake, and the only safe reading is that no
// verification happened. Accepting the submission would leave the one anonymous
// write endpoint unguarded.
func TestSubmitRefusesWhenNoVerifierIsWired(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{}
	service := newService(requests, &fakeUsers{}, &fakeAudit{}, nil)
	service.Captcha = nil

	_, err := service.Submit(context.Background(), validSubmit())
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindUnavailable {
		t.Fatalf("Submit() with no verifier error = %v, want KindUnavailable", err)
	}
	if requests.created != nil {
		t.Fatal("a ticket was stored without verification")
	}
}

// Both the personal and the login address are checked. The login address becomes
// the account's identity and V005's triggers also forbid it from already existing
// as someone's other_mail binding.
func TestSubmitChecksBothAddressesForOccupancy(t *testing.T) {
	t.Parallel()

	users := &fakeUsers{}
	service := newService(&fakeRequests{}, users, &fakeAudit{}, &fakeCaptcha{})

	if _, err := service.Submit(context.Background(), validSubmit()); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	for _, want := range []string{"zhangsan@example.com", "b20040101@njupt.edu.cn"} {
		found := false
		for _, queried := range users.emailQueries {
			if queried == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("occupancy queries = %v, want them to include %q", users.emailQueries, want)
		}
	}
}

func TestSubmitReportsOccupiedIdentifiers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		users    *fakeUsers
		wantCode int
	}{
		{
			name:     "personal email taken",
			users:    &fakeUsers{occupiedEmails: map[string]bool{"zhangsan@example.com": true}},
			wantCode: errcode.CodeEmailAlreadyRegistered,
		},
		{
			name:     "login email taken",
			users:    &fakeUsers{occupiedEmails: map[string]bool{"b20040101@njupt.edu.cn": true}},
			wantCode: errcode.CodeEmailAlreadyRegistered,
		},
		{
			name:     "student id taken",
			users:    &fakeUsers{occupiedIDs: map[string]bool{"B20040101": true}},
			wantCode: errcode.CodeStudentIDOccupied,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			service := newService(&fakeRequests{}, testCase.users, &fakeAudit{}, &fakeCaptcha{})

			_, err := service.Submit(context.Background(), validSubmit())
			if errorCode(err) != testCase.wantCode {
				t.Fatalf("code = %d, want %d (error %v)", errorCode(err), testCase.wantCode, err)
			}
		})
	}
}

// The partial unique index is the expected collision: the applicant submitted
// twice. It has to read as "your application is still open" rather than a generic
// conflict, because a rejected applicant is allowed to resubmit.
func TestSubmitMapsThePendingStudentIndex(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{createErr: uniqueViolation(pendingStudentConstraint)}
	service := newService(requests, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

	_, err := service.Submit(context.Background(), validSubmit())
	if errorCode(err) != errcode.CodeAlumniRequestPending {
		t.Fatalf("code = %d, want %d (error %v)", errorCode(err), errcode.CodeAlumniRequestPending, err)
	}
}

// Two rate-limit buckets: per IP so one host cannot flood the queue, and per
// student ID so a distributed retry cannot do it under one identity.
func TestSubmitLimitsByIPAndStudentID(t *testing.T) {
	t.Parallel()

	limiter := &fakeLimiter{}
	service := newService(&fakeRequests{}, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})
	service.Limiter = limiter
	service.SubmitRateLimit = 3

	if _, err := service.Submit(context.Background(), validSubmit()); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	want := []string{"ip:203.0.113.7", "student:B20040101"}
	if len(limiter.subjects) != len(want) {
		t.Fatalf("limiter subjects = %v, want %v", limiter.subjects, want)
	}
	for i, subject := range want {
		if limiter.subjects[i] != subject {
			t.Fatalf("limiter subject[%d] = %q, want %q", i, limiter.subjects[i], subject)
		}
	}
}

func TestSubmitReportsRateLimiting(t *testing.T) {
	t.Parallel()

	limiter := &fakeLimiter{deny: map[string]bool{"ip:203.0.113.7": true}}
	requests := &fakeRequests{}
	service := newService(requests, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})
	service.Limiter = limiter
	service.SubmitRateLimit = 3

	_, err := service.Submit(context.Background(), validSubmit())
	if errorCode(err) != errcode.CodeRateLimited {
		t.Fatalf("code = %d, want %d", errorCode(err), errcode.CodeRateLimited)
	}
	if requests.created != nil {
		t.Fatal("a ticket was stored despite the rate limit")
	}
}

// The limiter is fail-open per the PRD's rate-limit class: losing the counter only
// widens the window, while failing closed would let a Redis outage take down the
// only intake path graduated members have. The captcha still stands in front.
func TestSubmitProceedsWhenTheLimiterIsUnavailable(t *testing.T) {
	t.Parallel()

	limiter := &fakeLimiter{err: errors.New("redis down")}
	requests := &fakeRequests{}
	service := newService(requests, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})
	service.Limiter = limiter
	service.SubmitRateLimit = 3

	if _, err := service.Submit(context.Background(), validSubmit()); err != nil {
		t.Fatalf("Submit() with a broken limiter error = %v, want nil", err)
	}
	if requests.created == nil {
		t.Fatal("the ticket was not stored")
	}
}

// A submission is unauthenticated: user_id must stay NULL rather than being
// attributed to anyone, and actor_client_id must stay NULL rather than naming the
// console — no OAuth credential authorized this.
func TestSubmitAuditsWithNoActor(t *testing.T) {
	t.Parallel()

	audit := &fakeAudit{}
	service := newService(&fakeRequests{}, &fakeUsers{}, audit, &fakeCaptcha{})

	if _, err := service.Submit(context.Background(), validSubmit()); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	entry := audit.find(actionSubmit)
	if entry == nil {
		t.Fatalf("audit actions = %v, want %s", audit.actions(), actionSubmit)
	}
	if entry.UserID != nil {
		t.Fatalf("audit user_id = %v, want NULL for an anonymous submission", *entry.UserID)
	}
	if entry.ActorClientID != nil {
		t.Fatalf("audit actor_client_id = %v, want NULL: no credential authorized this",
			*entry.ActorClientID)
	}
	if entry.Success == nil || !*entry.Success {
		t.Fatal("audit success = false, want true")
	}
	if !strings.Contains(string(entry.Detail), "captcha") {
		t.Fatalf("audit detail = %s, want the captcha verdict recorded", entry.Detail)
	}
}

// The captcha token is a bearer value for the verification. Single-use or not, it
// has no place in a durable log.
func TestSubmitNeverAuditsTheCaptchaToken(t *testing.T) {
	t.Parallel()

	audit := &fakeAudit{}
	service := newService(&fakeRequests{}, &fakeUsers{}, audit, &fakeCaptcha{})

	if _, err := service.Submit(context.Background(), validSubmit()); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	for _, entry := range audit.entries {
		if strings.Contains(string(entry.Detail), "captcha-token") {
			t.Fatalf("audit detail leaked the token: %s", entry.Detail)
		}
	}
}

// A failed submission is audited too, or an abuse pattern leaves no trace.
func TestSubmitAuditsFailures(t *testing.T) {
	t.Parallel()

	audit := &fakeAudit{}
	service := newService(&fakeRequests{},
		&fakeUsers{occupiedIDs: map[string]bool{"B20040101": true}}, audit, &fakeCaptcha{})

	if _, err := service.Submit(context.Background(), validSubmit()); err == nil {
		t.Fatal("Submit() error = nil, want a conflict")
	}
	entry := audit.find(actionSubmit)
	if entry == nil {
		t.Fatalf("audit actions = %v, want a failure row", audit.actions())
	}
	if entry.Success == nil || *entry.Success {
		t.Fatal("audit success = true, want false")
	}
	if entry.ErrCode == nil || *entry.ErrCode != errcode.CodeStudentIDOccupied {
		t.Fatalf("audit err_code = %v, want %d", entry.ErrCode, errcode.CodeStudentIDOccupied)
	}
}

// assertInvalidInput checks the error is a 400-class refusal naming the field.
func assertInvalidInput(t *testing.T, err error, field string) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want a typed error", err)
	}
	if typed.Kind != KindInvalidInput {
		t.Fatalf("kind = %s, want %s", typed.Kind, KindInvalidInput)
	}
	if !strings.Contains(typed.Message, field) {
		t.Fatalf("message = %q, want it to name %q", typed.Message, field)
	}
}

// uniqueViolation builds the driver error a unique-index collision produces, so the
// classification path under test is the real one rather than a stub.
func uniqueViolation(constraint string) error {
	return repository.NewUniqueViolationForTest(constraint)
}
