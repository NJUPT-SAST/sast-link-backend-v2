package model

import "time"

// AlumniRequestStatus is the review state of an account-request ticket.
type AlumniRequestStatus string

const (
	AlumniRequestStatusPending  AlumniRequestStatus = "pending"
	AlumniRequestStatusApproved AlumniRequestStatus = "approved"
	AlumniRequestStatusRejected AlumniRequestStatus = "rejected"
)

// Valid reports whether s is a defined alumni_request_status_enum value.
//
// Needed for the same reason College.Valid is: an undefined value reaches
// PostgreSQL as an invalid input for the enum, which surfaces as a 500 naming no
// field rather than a 400 naming the parameter.
func (s AlumniRequestStatus) Valid() bool {
	switch s {
	case AlumniRequestStatusPending, AlumniRequestStatusApproved, AlumniRequestStatusRejected:
		return true
	default:
		return false
	}
}

// AlumniRequest persists one alumni account-request ticket.
//
// The ticket carries two addresses because a graduated member's school mailbox is
// usually the reason they are here: LoginEmail is the original @njupt.edu.cn or
// @sast.fun address that becomes the account's login identity, and PersonalEmail
// is a reachable third-party mailbox bound as an other_mail identity. Result
// notifications go to PersonalEmail - sending them to LoginEmail would deliver
// them to the dead mailbox.
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
	Status         AlumniRequestStatus `gorm:"type:alumni_request_status_enum;not null;default:(-)"`
	RejectReason   string
	// CreatedUserID is the provisioned account, set when the ticket is approved.
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
