package model

import "time"

// AlumniRequestStatus is the review state of an account-request ticket.
type AlumniRequestStatus string

const (
	AlumniRequestStatusPending  AlumniRequestStatus = "pending"
	AlumniRequestStatusApproved AlumniRequestStatus = "approved"
	AlumniRequestStatusRejected AlumniRequestStatus = "rejected"
)

// Valid reports whether s is a defined alumni_request_status_enum value, so an
// undefined value fails as a 400 naming the parameter rather than a PostgreSQL
// enum 500.
func (s AlumniRequestStatus) Valid() bool {
	switch s {
	case AlumniRequestStatusPending, AlumniRequestStatusApproved, AlumniRequestStatusRejected:
		return true
	default:
		return false
	}
}

// AlumniRequestIntent is what approval does with a ticket. TEXT in the schema
// (V013) rather than an enum type: written once at submission, never mutated,
// and the rules live here.
type AlumniRequestIntent string

const (
	// AlumniRequestIntentProvision opens a new account — the original and only
	// behavior through V011.
	AlumniRequestIntentProvision AlumniRequestIntent = "provision"
	// AlumniRequestIntentRecover restores access to the account the student ID
	// already holds: approval binds PersonalEmail as that account's other_mail
	// identity instead of provisioning. The dead-end it serves is the alumnus
	// whose school mailbox died before they ever bound anything: they need
	// access restored to account #1, not a second account.
	AlumniRequestIntentRecover AlumniRequestIntent = "recover"
)

// Valid reports whether i is a defined intent value.
func (i AlumniRequestIntent) Valid() bool {
	switch i {
	case AlumniRequestIntentProvision, AlumniRequestIntentRecover:
		return true
	default:
		return false
	}
}

// AlumniRequest persists one alumni account-request ticket.
//
// It carries two addresses: LoginEmail is the original @njupt.edu.cn or @sast.fun
// address that becomes the account's login identity, and PersonalEmail is a
// reachable third-party mailbox bound as an other_mail identity. Result
// notifications go only to PersonalEmail — LoginEmail is the dead mailbox.
type AlumniRequest struct {
	ID             int64
	Name           string
	StudentID      string
	LoginEmail     string
	PersonalEmail  string
	PhoneNumber    string
	QQNumber       string
	College        College `gorm:"type:college_enum;not null;default:(-)"`
	Major          string
	JoinYear       string
	DepartmentNote string
	Note           string
	// Intent selects what approval does; defaults to provision both in the
	// schema (old rows read back as provision) and at submission.
	Intent       AlumniRequestIntent `gorm:"not null;default:'provision'"`
	Status       AlumniRequestStatus `gorm:"type:alumni_request_status_enum;not null;default:(-)"`
	RejectReason string
	// CreatedUserID is the account approval acted on: provisioned for a
	// provision ticket, recovered (the existing account) for a recover one.
	// NULL both before approval and after that account is closed, since the FK is
	// ON DELETE SET NULL so ticket history outlives the account.
	CreatedUserID *int64
	ReviewedBy    *int64
	ReviewedAt    *time.Time
	// NotifiedAt records that the result email was confirmed sent. NULL is the
	// backlog marker the console filters on.
	NotifiedAt *time.Time
	// NotifyAttempts is incremented before each send, so a process killed mid-send
	// leaves evidence that it tried rather than losing the attempt.
	NotifyAttempts int
	// ClientIP is kept for abuse tracing and rate-limit forensics. It is
	// deliberately never returned in a response: it identifies the submitter's
	// network and reviewing a ticket has no use for it.
	ClientIP  string `gorm:"column:client_ip"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TableName returns the exact V011 table name for AlumniRequest.
func (AlumniRequest) TableName() string {
	return "alumni_requests"
}
