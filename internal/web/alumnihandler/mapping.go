package alumnihandler

import (
	"errors"
	"net/http"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/alumnirequest"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

// AdminRole is the role permitted on the review endpoints, exported so the
// composition root cannot silently mount them behind a different one.
const AdminRole = model.UserRoleAdmin

// ReaderRoles are the roles permitted to read the queue. Same set that may
// read the user directory, since a pending ticket is a prospective directory
// entry; acting on a ticket is admin-only.
var ReaderRoles = []model.UserRole{model.UserRoleAdmin, model.UserRoleLecturer}

// ReadScopes and WriteScopes are the delegated scopes each class of route
// accepts. admin:write appears in ReadScopes because write implies read.
var (
	ReadScopes  = []string{scope.AdminRead, scope.AdminWrite}
	WriteScopes = []string{scope.AdminWrite}
)

// requestDTO is a ticket as the console sees it. No client_ip field: the
// submitter's address is kept for abuse tracing, and reviewing a ticket has no
// use for it — copying it onto a read surface would widen who can see a network
// identifier tied to a named individual.
type requestDTO struct {
	ID             int64      `json:"id"`
	Name           string     `json:"name"`
	StudentID      string     `json:"student_id"`
	LoginEmail     string     `json:"login_email"`
	PersonalEmail  string     `json:"personal_email"`
	PhoneNumber    string     `json:"phone_number"`
	QQNumber       string     `json:"qq_number"`
	College        string     `json:"college"`
	Major          string     `json:"major"`
	JoinYear       string     `json:"join_year"`
	DepartmentNote string     `json:"department_note"`
	Note           string     `json:"note"`
	Status         string     `json:"status"`
	RejectReason   string     `json:"reject_reason"`
	CreatedUserID  *int64     `json:"created_user_id"`
	ReviewedBy     *int64     `json:"reviewed_by"`
	ReviewedAt     *time.Time `json:"reviewed_at"`
	// NotifiedAt is null until the result email is confirmed sent, which is what the
	// console filters on to find the notification backlog.
	NotifiedAt     *time.Time `json:"notified_at"`
	NotifyAttempts int        `json:"notify_attempts"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// listDTO is one page of the queue.
type listDTO struct {
	Requests []requestDTO `json:"requests"`
	Total    int64        `json:"total"`
	Page     int          `json:"page"`
	PageSize int          `json:"page_size"`
}

func mapRequest(view alumnirequest.RequestView) requestDTO {
	return requestDTO{
		ID:             view.ID,
		Name:           view.Name,
		StudentID:      view.StudentID,
		LoginEmail:     view.LoginEmail,
		PersonalEmail:  view.PersonalEmail,
		PhoneNumber:    view.PhoneNumber,
		QQNumber:       view.QQNumber,
		College:        view.College,
		Major:          view.Major,
		JoinYear:       view.JoinYear,
		DepartmentNote: view.DepartmentNote,
		Note:           view.Note,
		Status:         view.Status,
		RejectReason:   view.RejectReason,
		CreatedUserID:  view.CreatedUserID,
		ReviewedBy:     view.ReviewedBy,
		ReviewedAt:     view.ReviewedAt,
		NotifiedAt:     view.NotifiedAt,
		NotifyAttempts: view.NotifyAttempts,
		CreatedAt:      view.CreatedAt,
		UpdatedAt:      view.UpdatedAt,
	}
}

// mapRequests always returns a slice, never nil: a nil marshals to JSON null and
// every client iterating the field would need a special case for an empty queue.
func mapRequests(views []alumnirequest.RequestView) []requestDTO {
	rows := make([]requestDTO, 0, len(views))
	for _, view := range views {
		rows = append(rows, mapRequest(view))
	}
	return rows
}

// mapServiceError converts a typed alumnirequest error into the HTTP envelope.
// The captcha and unavailable kinds must not collapse into one status: 400 tells
// the submitter to solve the challenge again, 503 tells the client verification
// is not running at all and the entry point should be hidden.
func mapServiceError(err error) error {
	var serviceErr *alumnirequest.Error
	if !errors.As(err, &serviceErr) {
		return internalError()
	}
	status := http.StatusInternalServerError
	message := errcode.Messages[errcode.CodeInternal]
	switch serviceErr.Kind {
	case alumnirequest.KindInvalidInput:
		status = http.StatusBadRequest
		// The service's messages are literals naming which rule was broken, never
		// echoes of submitted values, so they are safe to return verbatim.
		message = serviceErr.Message
	case alumnirequest.KindNotFound:
		status = http.StatusNotFound
		message = errcode.Messages[errcode.CodeAlumniRequestNotFound]
	case alumnirequest.KindConflict:
		status = http.StatusConflict
		message = serviceErr.Message
	case alumnirequest.KindStateConflict:
		// 422 rather than 409: the request is well formed and the ticket exists; the
		// transition is what its current status does not allow.
		status = http.StatusUnprocessableEntity
		message = serviceErr.Message
	case alumnirequest.KindCaptchaFailed:
		status = http.StatusBadRequest
		message = serviceErr.Message
	case alumnirequest.KindUnavailable:
		status = http.StatusServiceUnavailable
		message = serviceErr.Message
	case alumnirequest.KindRateLimited:
		status = http.StatusTooManyRequests
		message = serviceErr.Message
	case alumnirequest.KindInternal:
	}
	code := serviceErr.Code
	if code == 0 {
		code = errcode.CodeInternal
	}
	return &response.BusinessError{HTTPStatus: status, Code: code, Message: message}
}
