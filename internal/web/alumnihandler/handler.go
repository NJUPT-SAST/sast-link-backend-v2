// Package alumnihandler exposes the alumni account-request endpoints over HTTP.
//
// One anonymous endpoint and five console ones. The anonymous one is the only
// unauthenticated write in the service, which is why its human-verification check
// is not optional and its request body is decoded strictly.
package alumnihandler

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/alumnirequest"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/webutil"
)

// RequestService is the account-request use cases this handler exposes.
type RequestService interface {
	Submit(ctx context.Context, input alumnirequest.SubmitInput) (*alumnirequest.SubmitResult, error)
	List(ctx context.Context, input alumnirequest.ListInput) (*alumnirequest.ListResult, error)
	Get(ctx context.Context, requestID int64) (*alumnirequest.RequestView, error)
	Approve(ctx context.Context, input alumnirequest.ReviewInput) (*alumnirequest.ApproveResult, error)
	Reject(ctx context.Context, input alumnirequest.ReviewInput) (*alumnirequest.ReviewResult, error)
	ResendNotification(ctx context.Context, input alumnirequest.ReviewInput) (*alumnirequest.ReviewResult, error)
}

// Handler serves the account-request endpoints.
type Handler struct {
	Requests RequestService
}

// Gates are the middleware the console routes are mounted behind. A struct
// rather than positional parameters, for the reason adminhandler.Gates gives:
// a transposed pair would compile into a route gated by the wrong permission.
//
// There is no captcha gate here. The human-verification check is a service-layer
// port, because its verdict belongs in the same audit row as the submission and
// it must run after field validation — a middleware necessarily runs before the
// handler decodes the body, and a Turnstile token is single-use.
type Gates struct {
	RequireAuth       gin.HandlerFunc
	RequireReadScope  gin.HandlerFunc
	RequireWriteScope gin.HandlerFunc
	RequireAdmin      gin.HandlerFunc
}

// RegisterRoutes mounts the account-request endpoints.
//
// The public submission sits at the root with no gate: it is reached by people
// who have no account by definition; its protection is the service's captcha
// check and rate limiter.
//
// Every console route names both a scope gate and the role gate, and the role
// gate is admin for all of them: a ticket carries an applicant's contact
// details and prospective identity, so the queue — reads included — is not a
// directory view for lecturers.
func RegisterRoutes(r gin.IRouter, h Handler, g Gates) {
	// Panic at boot rather than serve an ungated console route.
	if g.RequireAuth == nil || g.RequireReadScope == nil || g.RequireWriteScope == nil ||
		g.RequireAdmin == nil {
		panic("alumnihandler: every gate in Gates must be set")
	}

	r.POST("/alumni-requests", h.Submit)

	admin := r.Group("/admin", g.RequireAuth)
	admin.GET("/alumni-requests", g.RequireReadScope, g.RequireAdmin, h.List)
	admin.GET("/alumni-requests/:id", g.RequireReadScope, g.RequireAdmin, h.Get)
	admin.POST("/alumni-requests/:id/approve", g.RequireWriteScope, g.RequireAdmin, h.Approve)
	admin.POST("/alumni-requests/:id/reject", g.RequireWriteScope, g.RequireAdmin, h.Reject)
	admin.POST("/alumni-requests/:id/resend-notification",
		g.RequireWriteScope, g.RequireAdmin, h.ResendNotification)
}

// submitRequest is the anonymous submission body. Every field has no binding
// tags: the service owns the rules, so a binding:"required" here would produce a
// second, weaker copy that reports a different message for the same violation.
type submitRequest struct {
	Name           string  `json:"name"`
	StudentID      string  `json:"student_id"`
	LoginEmail     string  `json:"login_email"`
	PersonalEmail  string  `json:"personal_email"`
	PhoneNumber    string  `json:"phone_number"`
	QQNumber       string  `json:"qq_number"`
	College        *string `json:"college"`
	Major          string  `json:"major"`
	JoinYear       string  `json:"join_year"`
	DepartmentNote string  `json:"department_note"`
	Note           string  `json:"note"`
	CaptchaToken   string  `json:"captcha_token"`
}

// submittedDTO is all an anonymous submitter learns: the ticket id. Nothing about
// the account that may or may not exist behind the identifiers they supplied.
type submittedDTO struct {
	ID int64 `json:"id"`
}

// Submit records an account-request ticket.
func (h Handler) Submit(c *gin.Context) {
	var req submitRequest
	if err := webutil.DecodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Requests.Submit(c.Request.Context(), alumnirequest.SubmitInput{
		Name:           req.Name,
		StudentID:      req.StudentID,
		LoginEmail:     req.LoginEmail,
		PersonalEmail:  req.PersonalEmail,
		PhoneNumber:    req.PhoneNumber,
		QQNumber:       req.QQNumber,
		College:        req.College,
		Major:          req.Major,
		JoinYear:       req.JoinYear,
		DepartmentNote: req.DepartmentNote,
		Note:           req.Note,
		CaptchaToken:   req.CaptchaToken,
		ClientIP:       c.ClientIP(),
		UserAgent:      c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, submittedDTO{ID: result.RequestID})
}

// List returns the reviewer's queue.
func (h Handler) List(c *gin.Context) {
	notified, err := parseOptionalBool(c.Query("notified"))
	if err != nil {
		response.Error(c, badRequest())
		return
	}
	input := alumnirequest.ListInput{
		Notified: notified,
		Keyword:  c.Query("keyword"),
	}
	page, pageSize, err := web.ParsePaging(c)
	if err != nil {
		response.Error(c, badRequest())
		return
	}
	input.Page, input.PageSize = page, pageSize
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		input.Status = &status
	}
	result, err := h.Requests.List(c.Request.Context(), input)
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, listDTO{
		Requests: mapRequests(result.Requests),
		Total:    result.Total,
		Page:     result.Page,
		PageSize: result.PageSize,
	})
}

// Get returns one ticket.
func (h Handler) Get(c *gin.Context) {
	requestID, ok := parseID(c)
	if !ok {
		response.Error(c, notFound())
		return
	}
	view, err := h.Requests.Get(c.Request.Context(), requestID)
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, mapRequest(*view))
}

// approvedDTO reports the provisioned account. No initial_password field: the
// generated password is discarded at approval time and the applicant sets their
// own through the reset flow.
// serialize.
type approvedDTO struct {
	UserID     int64  `json:"user_id"`
	LoginEmail string `json:"login_email"`
	// NotifyEnqueued answers "did the email make it into the queue", which is not
	// the same as "was it delivered". False tells the console to offer a resend.
	NotifyEnqueued bool `json:"notify_enqueued"`
}

// notifyDTO is the outcome of a rejection or a resend.
type notifyDTO struct {
	NotifyEnqueued bool `json:"notify_enqueued"`
}

// Approve provisions the account and records the verdict.
func (h Handler) Approve(c *gin.Context) {
	input, ok := h.reviewInput(c)
	if !ok {
		return
	}
	if err := decodeOptionalStrictJSON(c, &emptyRequest{}); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Requests.Approve(c.Request.Context(), input)
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, approvedDTO{
		UserID:         result.UserID,
		LoginEmail:     result.LoginEmail,
		NotifyEnqueued: result.NotifyEnqueued,
	})
}

// rejectRequest carries the reason the applicant is told.
type rejectRequest struct {
	RejectReason string `json:"reject_reason"`
}

// Reject records a rejection.
func (h Handler) Reject(c *gin.Context) {
	input, ok := h.reviewInput(c)
	if !ok {
		return
	}
	var req rejectRequest
	if err := webutil.DecodeStrictJSON(c, &req); err != nil {
		response.Error(c, badRequest())
		return
	}
	input.Reason = req.RejectReason

	result, err := h.Requests.Reject(c.Request.Context(), input)
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, notifyDTO{NotifyEnqueued: result.NotifyEnqueued})
}

// ResendNotification re-queues the result email.
func (h Handler) ResendNotification(c *gin.Context) {
	input, ok := h.reviewInput(c)
	if !ok {
		return
	}
	if err := decodeOptionalStrictJSON(c, &emptyRequest{}); err != nil {
		response.Error(c, badRequest())
		return
	}
	result, err := h.Requests.ResendNotification(c.Request.Context(), input)
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, notifyDTO{NotifyEnqueued: result.NotifyEnqueued})
}

// reviewInput resolves the reviewer and the ticket id, answering on the context
// when either is missing.
func (h Handler) reviewInput(c *gin.Context) (alumnirequest.ReviewInput, bool) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return alumnirequest.ReviewInput{}, false
	}
	requestID, ok := parseID(c)
	if !ok {
		response.Error(c, notFound())
		return alumnirequest.ReviewInput{}, false
	}
	return alumnirequest.ReviewInput{
		RequestID:     requestID,
		AdminUserID:   principal.UserID,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	}, true
}

// emptyRequest is the only accepted object for review actions without fields.
type emptyRequest struct{}

// decodeOptionalStrictJSON accepts an empty body or a strict JSON object.
func decodeOptionalStrictJSON(c *gin.Context, destination any) error {
	if c.Request.Body == nil {
		return nil
	}
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, webutil.MaxJSONRequestBodyBytes))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	if err := webutil.RequireJSONContentType(c); err != nil {
		return err
	}
	return webutil.DecodeStrictJSONBytes(body, destination)
}

// parseID reads a positive numeric :id. A non-numeric path segment is a 404
// rather than a 400: it names no ticket.
func parseID(c *gin.Context) (int64, bool) {
	// Delegate to web.ParsePositiveID rather than reimplementing it: it rejects
	// non-digits (including a "+" prefix) and values <= 0 in a single rule.
	return web.ParsePositiveID(c.Param("id"))
}

// parseOptionalBool accepts only "true" and "false".
//
// strconv.ParseBool would also take "1", "t" and "T", which the contract
// does not document; an unrecognized value is an error rather than a silent
// false, so a mistyped notified=ture returns the opposite of what was asked.
func parseOptionalBool(raw string) (*bool, error) {
	switch strings.TrimSpace(raw) {
	case "":
		return nil, nil
	case "true":
		value := true
		return &value, nil
	case "false":
		value := false
		return &value, nil
	default:
		return nil, errors.New("alumnihandler: notified must be true or false")
	}
}

func internalError() error {
	return webutil.InternalError()
}

func badRequest() error {
	return webutil.BadRequest()
}

func notFound() error {
	return webutil.NotFound(errcode.CodeAlumniRequestNotFound, errcode.Messages[errcode.CodeAlumniRequestNotFound])
}
