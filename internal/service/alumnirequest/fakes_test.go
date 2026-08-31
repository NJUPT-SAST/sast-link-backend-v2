package alumnirequest

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// fakeClock is a fixed time source so audit rows and reviewed_at are assertable.
type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

var testNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

// fakeRequests records what the service asked of the repository.
type fakeRequests struct {
	mu sync.Mutex

	created     *model.AlumniRequest
	createErr   error
	nextID      int64
	getResult   *model.AlumniRequest
	getErr      error
	listRows    []model.AlumniRequest
	listTotal   int64
	listErr     error
	listFilter  repository.AlumniRequestFilter
	approveErr  error
	approved    *model.AlumniRequest
	rejectErr   error
	rejected    *model.AlumniRequest
	rejectedFor string
	// pendingEmail is the fake's answer to EmailHasPendingTicket; the query's
	// input is recorded in pendingEmailArg.
	pendingEmail    bool
	pendingEmailErr error
	pendingEmailArg string
	// provisioned captures what the approval callback built, which is how the tests
	// check the role, state and identity the account was created with.
	provisioned *model.User
	identity    *model.Identity
	// recoverApproved records that the recovery path ran, with the target user ID
	// it wrote into created_user_id.
	recoverApproved bool
	recoverTargetID int64
}

func (f *fakeRequests) Create(_ context.Context, request *model.AlumniRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return f.createErr
	}
	if f.nextID == 0 {
		f.nextID = 7
	}
	request.ID = f.nextID
	f.created = request
	return nil
}

func (f *fakeRequests) Get(_ context.Context, _ int64) (*model.AlumniRequest, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getResult == nil {
		// Approval flows read the ticket before locking it; a test that did not
		// configure one is still given an existing pending ticket to act on.
		return pendingTicket(), nil
	}
	return f.getResult, nil
}

func (f *fakeRequests) List(
	_ context.Context,
	filter repository.AlumniRequestFilter,
) ([]model.AlumniRequest, int64, error) {
	f.listFilter = filter
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return f.listRows, f.listTotal, nil
}

func (f *fakeRequests) EmailHasPendingTicket(_ context.Context, email string) (bool, error) {
	f.pendingEmailArg = email
	if f.pendingEmailErr != nil {
		return false, f.pendingEmailErr
	}
	return f.pendingEmail, nil
}

func (f *fakeRequests) ApproveAlumniRequest(
	_ context.Context,
	requestID int64,
	reviewerID int64,
	now time.Time,
	provision repository.AlumniProvision,
) (*model.AlumniRequest, error) {
	if f.approveErr != nil {
		return nil, f.approveErr
	}
	ticket := f.getResult
	if ticket == nil {
		ticket = pendingTicket()
	}
	user, profile, identity, err := provision(ticket)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, errors.New("provision returned no profile")
	}
	// Stand in for the INSERT assigning a key, so the caller's use of user.ID is
	// exercised rather than reading a zero.
	user.ID = 42
	f.provisioned = user
	f.identity = identity

	approved := *ticket
	approved.ID = requestID
	approved.Status = model.AlumniRequestStatusApproved
	approved.CreatedUserID = &user.ID
	approved.ReviewedBy = &reviewerID
	approved.ReviewedAt = &now
	f.approved = &approved
	return &approved, nil
}

func (f *fakeRequests) ApproveAlumniRequestRecover(
	_ context.Context,
	requestID int64,
	reviewerID int64,
	now time.Time,
) (*model.AlumniRequest, error) {
	if f.approveErr != nil {
		return nil, f.approveErr
	}
	ticket := f.getResult
	if ticket == nil {
		ticket = pendingTicket()
	}
	// Stand in for the existing account's key, distinct from every provisioned ID.
	target := ticket.ID + 900
	f.recoverApproved = true
	f.recoverTargetID = target

	approved := *ticket
	approved.ID = requestID
	approved.Status = model.AlumniRequestStatusApproved
	approved.CreatedUserID = &target
	approved.ReviewedBy = &reviewerID
	approved.ReviewedAt = &now
	f.approved = &approved
	return &approved, nil
}

func (f *fakeRequests) RejectAlumniRequest(
	_ context.Context,
	requestID int64,
	reviewerID int64,
	reason string,
	now time.Time,
) (*model.AlumniRequest, error) {
	if f.rejectErr != nil {
		return nil, f.rejectErr
	}
	ticket := f.getResult
	if ticket == nil {
		ticket = pendingTicket()
	}
	rejected := *ticket
	rejected.ID = requestID
	rejected.Status = model.AlumniRequestStatusRejected
	rejected.RejectReason = reason
	rejected.ReviewedBy = &reviewerID
	rejected.ReviewedAt = &now
	f.rejected = &rejected
	f.rejectedFor = reason
	return &rejected, nil
}

// fakeUsers answers the occupancy pre-checks.
type fakeUsers struct {
	occupiedEmails map[string]bool
	emailErr       error
	studentErr     error
	// loginEmailByStudentID feeds FindLoginEmailByStudentID; a test seeds the
	// exact ID string it expects the service to look up.
	loginEmailByStudentID map[string]string
	// emailQueries records every address asked about, so a test can assert that both
	// the personal and the login address were checked.
	emailQueries []string
}

func (f *fakeUsers) ExistsAsEmailAnywhere(_ context.Context, email string) (bool, error) {
	f.emailQueries = append(f.emailQueries, email)
	if f.emailErr != nil {
		return false, f.emailErr
	}
	return f.occupiedEmails[email], nil
}

func (f *fakeUsers) FindLoginEmailByStudentID(_ context.Context, studentID string) (string, bool, error) {
	if f.studentErr != nil {
		return "", false, f.studentErr
	}
	loginEmail, ok := f.loginEmailByStudentID[studentID]
	return loginEmail, ok, nil
}

// seedAccount registers an existing account under a student ID, as recovery
// submissions see it through the folded lookup.
func (f *fakeUsers) seedAccount(studentID, loginEmail string) {
	if f.loginEmailByStudentID == nil {
		f.loginEmailByStudentID = map[string]string{}
	}
	f.loginEmailByStudentID[studentID] = loginEmail
}

// fakeAudit collects audit rows.
type fakeAudit struct {
	mu      sync.Mutex
	entries []model.AuditLog
	err     error
}

func (f *fakeAudit) Create(_ context.Context, entry *model.AuditLog) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.entries = append(f.entries, *entry)
	return nil
}

func (f *fakeAudit) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(f.entries))
	for _, entry := range f.entries {
		names = append(names, entry.Action)
	}
	return names
}

func (f *fakeAudit) find(action string) *model.AuditLog {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.entries {
		if f.entries[i].Action == action {
			return &f.entries[i]
		}
	}
	return nil
}

// fakeHasher records the plaintext it was given so a test can prove the password
// never travels further than the hash.
type fakeHasher struct {
	seen []string
	err  error
}

func (f *fakeHasher) HashPassword(_ context.Context, password string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.seen = append(f.seen, password)
	return "argon2id$" + password, nil
}

// fakeCaptcha is the verification port.
type fakeCaptcha struct {
	err    error
	tokens []string
}

func (f *fakeCaptcha) Verify(_ context.Context, token, _ string) error {
	f.tokens = append(f.tokens, token)
	return f.err
}

// fakeLimiter allows or denies, and records the subjects it was asked about.
type fakeLimiter struct {
	deny     map[string]bool
	err      error
	subjects []string
}

func (f *fakeLimiter) Allow(_ context.Context, _ string, subject string) (LimitResult, error) {
	f.subjects = append(f.subjects, subject)
	if f.err != nil {
		return LimitResult{}, f.err
	}
	return LimitResult{Allowed: !f.deny[subject]}, nil
}

// fakeNotifier captures queued notifications.
type fakeNotifier struct {
	full bool
	jobs []NotificationJob
}

func (f *fakeNotifier) EnqueueAlumniNotification(job NotificationJob) bool {
	if f.full {
		return false
	}
	f.jobs = append(f.jobs, job)
	return true
}

// pendingTicket is a ticket that would pass validation.
func pendingTicket() *model.AlumniRequest {
	return &model.AlumniRequest{
		ID:             7,
		Name:           "张三",
		StudentID:      "B20040101",
		LoginEmail:     "b20040101@njupt.edu.cn",
		PersonalEmail:  "zhangsan@example.com",
		PhoneNumber:    "13800000000",
		QQNumber:       "10001",
		College:        model.CollegeOther,
		Major:          "计算机科学与技术",
		JoinYear:       "2020",
		Status:         model.AlumniRequestStatusPending,
		DepartmentNote: "技术部",
	}
}

// validSubmit is an input that passes every field rule.
//
// The captcha token is a challenge response, not a credential: it authenticates
// nothing and is spent once. gosec's G101 pattern-matches the field name, hence
// the exclusion.
//
//nolint:gosec // G101 false positive: a Turnstile response is not a secret.
func validSubmit() SubmitInput {
	return SubmitInput{
		Name:          "张三",
		StudentID:     "B20040101",
		LoginEmail:    "B20040101@njupt.edu.cn",
		PersonalEmail: "zhangsan@example.com",
		PhoneNumber:   "13800000000",
		QQNumber:      "10001",
		Major:         "计算机科学与技术",
		JoinYear:      "2020",
		CaptchaToken:  "captcha-token",
		ClientIP:      "203.0.113.7",
		UserAgent:     "test-agent",
	}
}

// newService wires a service with permissive fakes; tests tighten what they need.
func newService(
	requests *fakeRequests,
	users *fakeUsers,
	audit *fakeAudit,
	captcha *fakeCaptcha,
) Service {
	return Service{
		Requests:        requests,
		Users:           users,
		Audit:           audit,
		Passwords:       &fakeHasher{},
		Captcha:         captcha,
		Notifier:        &fakeNotifier{},
		Clock:           fakeClock{now: testNow},
		ConsoleClientID: "sast-link-web",
	}
}
