package alumnirequest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func reviewInput() ReviewInput {
	return ReviewInput{
		RequestID:   7,
		AdminUserID: 99,
		ClientIP:    "198.51.100.4",
		UserAgent:   "console",
	}
}

func TestApproveProvisionsARetiredMemberAccount(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{getResult: pendingTicket()}
	service := newService(requests, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

	result, err := service.Approve(context.Background(), reviewInput())
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if result.UserID != 42 {
		t.Fatalf("UserID = %d, want the persisted id", result.UserID)
	}

	user := requests.provisioned
	// Role and state are the console's provisioning defaults and are never taken
	// from the submission: a ticket must not be able to ask for a role.
	if user.Role != model.UserRoleMember {
		t.Fatalf("role = %s, want member", user.Role)
	}
	if user.State != model.UserStateRetiredSAST {
		t.Fatalf("state = %s, want retired_sast", user.State)
	}
	if user.LoginEmail != "b20040101@njupt.edu.cn" {
		t.Fatalf("login email = %q, want the ticket's school address", user.LoginEmail)
	}
	// The personal email is bound as an other_mail identity in the same
	// transaction, which is what makes the password-reset flow reach the applicant.
	if requests.identity == nil {
		t.Fatal("no identity was provisioned; the applicant could not reset a password")
	}
	if requests.identity.Provider != model.LoginMethodOtherMail ||
		requests.identity.ProviderID != "zhangsan@example.com" {
		t.Fatalf("identity = %+v, want an other_mail binding for the personal email",
			requests.identity)
	}
}

// V010's generated column is the reason major is mandatory on submission. This
// asserts the provisioned row carries values that clear it, so an approved alumnus
// lands on the home page rather than a completion prompt.
func TestApproveProvisionsACompleteProfile(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{getResult: pendingTicket()}
	service := newService(requests, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

	if _, err := service.Approve(context.Background(), reviewInput()); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	user := requests.provisioned
	for _, field := range []struct {
		name  string
		value string
	}{
		{"name", user.Name},
		{"phone_number", user.PhoneNumber},
		{"qq_number", user.QQNumber},
		{"major", user.Major},
	} {
		if strings.TrimSpace(field.value) == "" {
			t.Fatalf("%s is blank; V010 would flag the account as incomplete", field.name)
		}
	}
	if strings.EqualFold(user.Name, user.StudentID) {
		t.Fatal("name equals student_id; V010 would flag the account as incomplete")
	}
}

// The generated password exists only long enough to be hashed. It is not returned,
// not emailed and not audited: the applicant sets their own through the reset flow.
func TestApproveDiscardsTheGeneratedPassword(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{getResult: pendingTicket()}
	hasher := &fakeHasher{}
	audit := &fakeAudit{}
	notifier := &fakeNotifier{}
	service := newService(requests, &fakeUsers{}, audit, &fakeCaptcha{})
	service.Passwords = hasher
	service.Notifier = notifier

	if _, err := service.Approve(context.Background(), reviewInput()); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if len(hasher.seen) != 1 {
		t.Fatalf("hasher calls = %d, want 1", len(hasher.seen))
	}
	plaintext := hasher.seen[0]
	if plaintext == "" {
		t.Fatal("no password was generated")
	}
	// The stored hash must be a hash, not the plaintext.
	if requests.provisioned.PasswordHash == plaintext {
		t.Fatal("the plaintext password was stored")
	}
	for _, entry := range audit.entries {
		if strings.Contains(string(entry.Detail), plaintext) {
			t.Fatalf("audit detail carries the password: %s", entry.Detail)
		}
	}
	for _, job := range notifier.jobs {
		if strings.Contains(job.RejectReason, plaintext) || strings.Contains(job.Name, plaintext) {
			t.Fatal("a notification job carries the password")
		}
	}
}

// Approval writes two audit rows. The account creation does not go through
// adminuser.CreateUser, which is what would otherwise record it, so without the
// second row the trail contains an account nobody appears to have created.
func TestApproveAuditsBothTheVerdictAndTheAccountCreation(t *testing.T) {
	t.Parallel()

	audit := &fakeAudit{}
	service := newService(&fakeRequests{getResult: pendingTicket()}, &fakeUsers{}, audit, &fakeCaptcha{})

	if _, err := service.Approve(context.Background(), reviewInput()); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	verdict := audit.find(actionApprove)
	if verdict == nil {
		t.Fatalf("audit actions = %v, want %s", audit.actions(), actionApprove)
	}
	if verdict.Resource != auditResourceRequest {
		t.Fatalf("verdict resource = %q, want %q", verdict.Resource, auditResourceRequest)
	}
	creation := audit.find(actionCreateUser)
	if creation == nil {
		t.Fatalf("audit actions = %v, want %s", audit.actions(), actionCreateUser)
	}
	if creation.Resource != auditResourceUser {
		t.Fatalf("creation resource = %q, want %q", creation.Resource, auditResourceUser)
	}
	// The provenance marker is what distinguishes this from a console provisioning
	// of the same shape.
	if !strings.Contains(string(creation.Detail), "alumni_request") {
		t.Fatalf("creation detail = %s, want the ticket provenance recorded", creation.Detail)
	}
	// A review is authenticated, so unlike a submission both the reviewer and the
	// acting client are recorded.
	if verdict.UserID == nil || *verdict.UserID != 99 {
		t.Fatalf("verdict user_id = %v, want the reviewer", verdict.UserID)
	}
	if verdict.ActorClientID == nil || *verdict.ActorClientID != "sast-link-web" {
		t.Fatalf("verdict actor_client_id = %v, want the console client", verdict.ActorClientID)
	}
}

// The row lock turns the second half of a double-clicked approve into a refusal.
// It has to read as "already handled" rather than a generic conflict, so the
// console does not imply the reviewer did something wrong.
func TestApproveReportsAnAlreadyReviewedTicket(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{approveErr: repository.ErrStateConflict}
	service := newService(requests, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

	_, err := service.Approve(context.Background(), reviewInput())
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindStateConflict {
		t.Fatalf("Approve() error = %v, want KindStateConflict", err)
	}
	if typed.Code != errcode.CodeAlumniRequestReviewed {
		t.Fatalf("code = %d, want %d", typed.Code, errcode.CodeAlumniRequestReviewed)
	}
}

// The intent dispatch reads the stored ticket first, so a missing one fails at
// the lookup — the same not-found the reviewer would have seen from the queue.
func TestApproveReportsAMissingTicket(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{getErr: repository.ErrNotFound}
	service := newService(requests, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

	_, err := service.Approve(context.Background(), reviewInput())
	if errorCode(err) != errcode.CodeAlumniRequestNotFound {
		t.Fatalf("code = %d, want %d (error %v)",
			errorCode(err), errcode.CodeAlumniRequestNotFound, err)
	}
}

// A collision at approval means the pre-submission check lost a race with a
// registration. The reviewer needs to know which field, so the constraint name is
// classified rather than reported as a generic conflict.
func TestApproveMapsProvisioningCollisions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		constraint string
		wantCode   int
	}{
		{"user_login_email_key", errcode.CodeEmailAlreadyRegistered},
		{"ck_user_login_email_not_identity", errcode.CodeEmailAlreadyRegistered},
		{"uq_identities_provider_provider_id", errcode.CodeEmailAlreadyRegistered},
		{"user_student_id_key", errcode.CodeStudentIDOccupied},
	}
	for _, testCase := range cases {
		t.Run(testCase.constraint, func(t *testing.T) {
			t.Parallel()
			requests := &fakeRequests{
				approveErr: repository.NewUniqueViolationForTest(testCase.constraint),
			}
			service := newService(requests, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

			_, err := service.Approve(context.Background(), reviewInput())
			if errorCode(err) != testCase.wantCode {
				t.Fatalf("code = %d, want %d (error %v)", errorCode(err), testCase.wantCode, err)
			}
		})
	}
}

// A full queue must not fail a review that already committed: the account exists,
// and reporting an error would tell the reviewer their action did not happen.
// notify_enqueued=false routes them to the resend endpoint instead.
func TestApproveSucceedsWhenTheNotificationQueueIsFull(t *testing.T) {
	t.Parallel()

	service := newService(&fakeRequests{getResult: pendingTicket()}, &fakeUsers{},
		&fakeAudit{}, &fakeCaptcha{})
	service.Notifier = &fakeNotifier{full: true}

	result, err := service.Approve(context.Background(), reviewInput())
	if err != nil {
		t.Fatalf("Approve() with a full queue error = %v, want nil", err)
	}
	if result.NotifyEnqueued {
		t.Fatal("NotifyEnqueued = true, want false for a full queue")
	}
}

// The notification goes to the personal email. The login email is the deactivated
// school mailbox that caused the application, so sending there delivers nothing.
func TestApproveNotifiesThePersonalEmail(t *testing.T) {
	t.Parallel()

	notifier := &fakeNotifier{}
	service := newService(&fakeRequests{getResult: pendingTicket()}, &fakeUsers{},
		&fakeAudit{}, &fakeCaptcha{})
	service.Notifier = notifier

	if _, err := service.Approve(context.Background(), reviewInput()); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if len(notifier.jobs) != 1 {
		t.Fatalf("queued %d notifications, want 1", len(notifier.jobs))
	}
	job := notifier.jobs[0]
	if job.Recipient != "zhangsan@example.com" {
		t.Fatalf("recipient = %q, want the personal email", job.Recipient)
	}
	if !job.Approved {
		t.Fatal("job.Approved = false for an approval")
	}
}

// A rejection with no reason gives the applicant nothing to correct, and the whole
// premise of the flow is that they can fix their details and resubmit.
func TestRejectRequiresAReason(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{getResult: pendingTicket()}
	service := newService(requests, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

	input := reviewInput()
	input.Reason = "   "
	if _, err := service.Reject(context.Background(), input); err == nil {
		t.Fatal("Reject() with a blank reason error = nil, want a refusal")
	}
	if requests.rejected != nil {
		t.Fatal("the rejection was written despite a blank reason")
	}
}

// A rejection is notified too: without it the applicant waits indefinitely for a
// decision that has already been made.
func TestRejectNotifiesWithTheReason(t *testing.T) {
	t.Parallel()

	notifier := &fakeNotifier{}
	service := newService(&fakeRequests{getResult: pendingTicket()}, &fakeUsers{},
		&fakeAudit{}, &fakeCaptcha{})
	service.Notifier = notifier

	input := reviewInput()
	input.Reason = "学号与姓名不匹配"
	result, err := service.Reject(context.Background(), input)
	if err != nil {
		t.Fatalf("Reject() error = %v", err)
	}
	if !result.NotifyEnqueued {
		t.Fatal("NotifyEnqueued = false, want true")
	}
	job := notifier.jobs[0]
	if job.Approved {
		t.Fatal("job.Approved = true for a rejection")
	}
	if job.RejectReason != "学号与姓名不匹配" {
		t.Fatalf("job reason = %q, want the reviewer's reason", job.RejectReason)
	}
}

// There is no result to notify anyone about while a ticket is pending.
func TestResendRefusesAPendingTicket(t *testing.T) {
	t.Parallel()

	service := newService(&fakeRequests{getResult: pendingTicket()}, &fakeUsers{},
		&fakeAudit{}, &fakeCaptcha{})

	_, err := service.ResendNotification(context.Background(), reviewInput())
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindStateConflict {
		t.Fatalf("ResendNotification() on a pending ticket error = %v, want KindStateConflict", err)
	}
}

// Allowed even when notified_at is already set: an administrator asking for a
// resend knows something the system does not, usually that it never arrived.
func TestResendRepeatsADeliveredNotification(t *testing.T) {
	t.Parallel()

	ticket := pendingTicket()
	ticket.Status = model.AlumniRequestStatusApproved
	ticket.NotifiedAt = &testNow
	notifier := &fakeNotifier{}
	service := newService(&fakeRequests{getResult: ticket}, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})
	service.Notifier = notifier

	result, err := service.ResendNotification(context.Background(), reviewInput())
	if err != nil {
		t.Fatalf("ResendNotification() error = %v", err)
	}
	if !result.NotifyEnqueued || len(notifier.jobs) != 1 {
		t.Fatalf("NotifyEnqueued = %v with %d jobs, want a requeue",
			result.NotifyEnqueued, len(notifier.jobs))
	}
	if !notifier.jobs[0].Approved {
		t.Fatal("the resent job lost the approved verdict")
	}
}

// A recovery ticket's resend must select the restore-access copy, not the
// new-account one: the account was never opened by this flow.
func TestResendRecoveryRepeatsTheRecoveredCopy(t *testing.T) {
	t.Parallel()

	ticket := pendingTicket()
	ticket.ID = 15
	ticket.Status = model.AlumniRequestStatusApproved
	ticket.Intent = model.AlumniRequestIntentRecover
	ticket.NotifiedAt = &testNow
	notifier := &fakeNotifier{}
	service := newService(&fakeRequests{getResult: ticket}, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})
	service.Notifier = notifier

	if _, err := service.ResendNotification(context.Background(), reviewInput()); err != nil {
		t.Fatalf("ResendNotification() error = %v", err)
	}
	if len(notifier.jobs) != 1 || !notifier.jobs[0].Recovered {
		t.Fatalf("jobs = %+v, want one job with Recovered for a recover ticket", notifier.jobs)
	}
}

// An unrecognized status filter is refused rather than ignored. Dropping it would
// answer a filtered query with the unfiltered set, reading as "no pending tickets"
// when the truth is "you misspelled pending".
func TestListRejectsAnUnknownStatus(t *testing.T) {
	t.Parallel()

	service := newService(&fakeRequests{}, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})
	status := "pendign"
	if _, err := service.List(context.Background(), ListInput{Status: &status}); err == nil {
		t.Fatal("List() with a misspelled status error = nil, want a refusal")
	}
}

func TestListPassesFiltersAndPagingThrough(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{listRows: []model.AlumniRequest{*pendingTicket()}, listTotal: 1}
	service := newService(requests, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

	status := string(model.AlumniRequestStatusApproved)
	notified := false
	result, err := service.List(context.Background(), ListInput{
		Status:   &status,
		Notified: &notified,
		Keyword:  "张三",
		Page:     3,
		PageSize: 10,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if requests.listFilter.Status == nil ||
		*requests.listFilter.Status != model.AlumniRequestStatusApproved {
		t.Fatalf("status filter = %v, want approved", requests.listFilter.Status)
	}
	if requests.listFilter.Notified == nil || *requests.listFilter.Notified {
		t.Fatalf("notified filter = %v, want false", requests.listFilter.Notified)
	}
	if requests.listFilter.Offset != 20 || requests.listFilter.Limit != 10 {
		t.Fatalf("paging = offset %d limit %d, want 20/10",
			requests.listFilter.Offset, requests.listFilter.Limit)
	}
	if result.Total != 1 || len(result.Requests) != 1 {
		t.Fatalf("result = %d rows of %d, want 1 of 1", len(result.Requests), result.Total)
	}
}

// The page size is capped so a caller cannot ask for the whole table, and the
// repository refuses an over-cap limit outright rather than returning a
// differently sized page.
func TestListCapsPageSize(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{listRows: []model.AlumniRequest{}, listTotal: 0}
	service := newService(requests, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

	if _, err := service.List(context.Background(), ListInput{PageSize: 5000}); err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if requests.listFilter.Limit != 100 {
		t.Fatalf("limit = %d, want it capped at 100", requests.listFilter.Limit)
	}
}

// An empty page is a slice, not nil: nil marshals to JSON null and every client
// iterating the field would need a special case for an empty queue.
func TestListReturnsAnEmptySliceNotNil(t *testing.T) {
	t.Parallel()

	service := newService(&fakeRequests{listRows: nil, listTotal: 0}, &fakeUsers{},
		&fakeAudit{}, &fakeCaptcha{})

	result, err := service.List(context.Background(), ListInput{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if result.Requests == nil {
		t.Fatal("Requests = nil, want an empty slice")
	}
}

// ClientIP stays in the table for abuse tracing and is never copied onto a read
// surface: reviewing a ticket has no use for the submitter's network address.
func TestRequestViewOmitsTheSubmitterAddress(t *testing.T) {
	t.Parallel()

	ticket := pendingTicket()
	ticket.ClientIP = "203.0.113.7"
	requests := &fakeRequests{listRows: []model.AlumniRequest{*ticket}, listTotal: 1}
	service := newService(requests, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

	result, err := service.List(context.Background(), ListInput{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	view := result.Requests[0]
	if strings.Contains(view.Name+view.Note+view.DepartmentNote, "203.0.113.7") {
		t.Fatal("the submitter address leaked into the view")
	}
}

// A recovery approval must not touch the provisioning machinery: no account is
// created, no password discarded, and the audit row says so in one line.
func TestApproveRecoversInsteadOfProvisioning(t *testing.T) {
	t.Parallel()

	ticket := pendingTicket()
	ticket.ID = 9
	ticket.Intent = model.AlumniRequestIntentRecover
	requests := &fakeRequests{getResult: ticket}
	audit := &fakeAudit{}
	notifier := &fakeNotifier{}
	service := newService(requests, &fakeUsers{}, audit, &fakeCaptcha{})
	service.Notifier = notifier

	result, err := service.Approve(context.Background(), reviewInput())
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if !requests.recoverApproved {
		t.Fatal("the recovery repository path did not run")
	}
	if requests.provisioned != nil {
		t.Fatal("the provisioning callback ran for a recovery approval")
	}
	if result.UserID != requests.recoverTargetID {
		t.Fatalf("UserID = %d, want the recovered account %d", result.UserID, requests.recoverTargetID)
	}
	if len(notifier.jobs) != 1 || !notifier.jobs[0].Recovered {
		t.Fatalf("jobs = %+v, want one recovery notification", notifier.jobs)
	}

	entry := audit.find(actionApprove)
	if entry == nil {
		t.Fatalf("audit actions = %v, want an approve row", audit.actions())
	}
	detail := string(entry.Detail)
	for _, marker := range []string{"\"recovered\":true", "\"target_user_id\":"} {
		if !strings.Contains(detail, marker) {
			t.Fatalf("approve detail %q missing %s", detail, marker)
		}
	}
	if strings.Contains(detail, "admin_user_create") {
		t.Fatal("recovery approval wrote an account-creation row")
	}

	if created := audit.find(actionCreateUser); created != nil {
		t.Fatal("recovery approval audited an admin_user_create event")
	}
}

// The dispatch refuses to feed a recovery ticket into the provisioning path:
// the repository guards exist for exactly that misdirected call.
func TestApproveDispatchesOnStoredIntent(t *testing.T) {
	t.Parallel()

	ticket := pendingTicket()
	ticket.ID = 11
	requests := &fakeRequests{getResult: ticket}
	service := newService(requests, &fakeUsers{}, &fakeAudit{}, &fakeCaptcha{})

	if _, err := service.Approve(context.Background(), reviewInput()); err != nil {
		t.Fatalf("provision intent: Approve() error = %v", err)
	}
	if requests.recoverApproved {
		t.Fatal("a provision ticket took the recovery path")
	}
}
