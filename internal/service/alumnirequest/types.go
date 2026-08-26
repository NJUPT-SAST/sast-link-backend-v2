package alumnirequest

import (
	"context"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// Audit resources and actions for this service.
const (
	auditResourceRequest = "alumni_request"
	// auditResourceUser is recorded alongside the approval so the account creation
	// appears in the audit trail — approval does not route through
	// adminuser.CreateUser, which is what would otherwise write it.
	auditResourceUser = "user"

	actionSubmit             = "alumni_request_submit"
	actionApprove            = "alumni_request_approve"
	actionReject             = "alumni_request_reject"
	actionResendNotification = "alumni_request_resend_notification"
	actionCreateUser         = "admin_user_create"
)

// limitScope names the rate-limit bucket for submissions.
const limitScope = "alumni_request"

// Requests persists account-request tickets.
type Requests interface {
	Create(ctx context.Context, request *model.AlumniRequest) error
	Get(ctx context.Context, requestID int64) (*model.AlumniRequest, error)
	List(ctx context.Context, filter repository.AlumniRequestFilter) ([]model.AlumniRequest, int64, error)
	// EmailHasPendingTicket reports whether a ticket awaiting review already
	// carries this address, so a submission cannot accumulate several pending
	// tickets under one personal email.
	EmailHasPendingTicket(ctx context.Context, email string) (bool, error)
	// ApproveAlumniRequest locks a provision ticket, provisions the account
	// through the callback, and writes the verdict in one transaction.
	ApproveAlumniRequest(
		ctx context.Context,
		requestID int64,
		reviewerID int64,
		now time.Time,
		provision repository.AlumniProvision,
	) (*model.AlumniRequest, error)
	// ApproveAlumniRequestRecover locks a recovery ticket, binds PersonalEmail as
	// the target account's other_mail identity, and writes the verdict in one
	// transaction. See repository.AlumniRequestRepository for the failure set.
	ApproveAlumniRequestRecover(
		ctx context.Context,
		requestID int64,
		reviewerID int64,
		now time.Time,
	) (*model.AlumniRequest, error)
	RejectAlumniRequest(
		ctx context.Context,
		requestID int64,
		reviewerID int64,
		reason string,
		now time.Time,
	) (*model.AlumniRequest, error)
}

// Users answers the occupancy questions a submission has to ask before it is
// accepted, so an applicant learns about a collision now rather than at review
// time.
type Users interface {
	// ExistsAsEmailAnywhere reports whether email is already a login email or an
	// other_mail binding on some account.
	ExistsAsEmailAnywhere(ctx context.Context, email string) (bool, error)
	// FindLoginEmailByStudentID resolves a student ID to the login email of the
	// account holding it, folding case and whitespace the same way the approval
	// transaction re-checks it. A recovery ticket requires the account to exist;
	// a provision ticket requires that it does not.
	FindLoginEmailByStudentID(ctx context.Context, studentID string) (string, bool, error)
}

// AuditLogRepository records audit events.
type AuditLogRepository interface {
	Create(ctx context.Context, entry *model.AuditLog) error
}

// PasswordHasher hashes the generated initial password; the alumnus sets their real
// password through the self-service reset flow.
type PasswordHasher interface {
	HashPassword(ctx context.Context, password string) (string, error)
}

// CaptchaVerifier is the human-verification check in front of submission. A
// service-layer port rather than middleware: the verdict belongs in the same audit
// record as the submission, and the check must run after field validation so a
// single-use token is not burned on a submission that then fails a length check.
// Implementations must distinguish a rejected token from an inability to check; see
// mapCaptchaError.
type CaptchaVerifier interface {
	Verify(ctx context.Context, token, remoteIP string) error
}

// LimitResult mirrors the limiter's outcome.
type LimitResult struct {
	Allowed bool
	TTL     time.Duration
}

// EndpointLimiter bounds submissions per IP and per student ID.
type EndpointLimiter interface {
	Allow(ctx context.Context, endpoint, subject string) (LimitResult, error)
}

// NotificationDispatcher hands result-email work to the background worker. Enqueue
// is non-blocking and returns false when the queue is full, which the caller reports
// as notify_enqueued rather than failing the review.
type NotificationDispatcher interface {
	EnqueueAlumniNotification(job NotificationJob) bool
}

// NotificationJob is one result email to deliver.
type NotificationJob struct {
	RequestID int64
	// Recipient is the applicant's personal email, never their login email: the
	// login address is the deactivated school mailbox that made them apply.
	Recipient    string
	Name         string
	Approved     bool
	RejectReason string
	// Recovered selects the restore-access copy instead of the new-account copy.
	Recovered bool
}

// SubmitInput is an anonymous account-request submission.
type SubmitInput struct {
	Name           string
	StudentID      string
	LoginEmail     string
	PersonalEmail  string
	PhoneNumber    string
	QQNumber       string
	College        *string
	Major          string
	JoinYear       string
	DepartmentNote string
	Note           string
	// Intent selects what approval should do; blank means provision. See
	// model.AlumniRequestIntent for the two values and what they imply for the
	// occupancy checks.
	Intent       string
	CaptchaToken string
	ClientIP     string
	UserAgent    string
}

// SubmitResult is the created ticket's id. Nothing else: the submitter is
// unauthenticated, so the response must not confirm anything about existing
// accounts beyond the conflict errors the flow already returns.
type SubmitResult struct {
	RequestID int64
}

// ListInput filters the reviewer's queue.
type ListInput struct {
	Status   *string
	Notified *bool
	Keyword  string
	Page     int
	PageSize int
}

// ListResult is one page of tickets.
type ListResult struct {
	Requests []RequestView
	Total    int64
	Page     int
	PageSize int
}

// RequestView is a ticket as the console sees it. ClientIP is deliberately absent:
// it stays in the table for abuse tracing, not on a read surface.
type RequestView struct {
	ID             int64
	Name           string
	StudentID      string
	LoginEmail     string
	PersonalEmail  string
	PhoneNumber    string
	QQNumber       string
	College        string
	Major          string
	JoinYear       string
	DepartmentNote string
	Note           string
	Status         string
	// Intent tells the console which approval action the ticket wants; recovery
	// tickets render as a high-scrutiny card because approving one touches an
	// existing account rather than minting a new one.
	Intent         string
	RejectReason   string
	CreatedUserID  *int64
	ReviewedBy     *int64
	ReviewedAt     *time.Time
	NotifiedAt     *time.Time
	NotifyAttempts int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ReviewInput identifies the reviewer for an approve, reject or resend.
type ReviewInput struct {
	RequestID int64
	// Reason is the rejection reason. Required for a rejection, ignored otherwise;
	// it reaches the applicant in the notification email.
	Reason string
	// AdminUserID is the authenticated reviewer, for the audit trail.
	AdminUserID int64
	// ActorClientID is the azp of the token that authorized the call. Empty means a
	// console session, which the audit records as ConsoleClientID.
	ActorClientID string
	ClientIP      string
	UserAgent     string
}

// ApproveResult reports the provisioned account. Deliberately not
// adminuser.CreateUserResult, which carries InitialPassword: the generated password
// is discarded here, so a struct with the field would risk putting one careless JSON
// tag between it and the wire.
type ApproveResult struct {
	UserID     int64
	LoginEmail string
	// NotifyEnqueued answers "did the email make it into the queue", which is not
	// the same question as notified_at's "was it delivered". A false here tells the
	// reviewer to use the resend endpoint.
	NotifyEnqueued bool
}

// ReviewResult is the outcome of a rejection or a resend.
type ReviewResult struct {
	NotifyEnqueued bool
}
