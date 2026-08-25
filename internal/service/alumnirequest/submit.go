package alumnirequest

import (
	"context"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// pendingStudentConstraint is V011's partial unique index: one open ticket per
// student ID.
const pendingStudentConstraint = "uq_alumni_requests_pending_student"

// Submit records an account-request ticket.
//
// Order matters and is not the obvious one. Field validation runs first, before
// the captcha, because a Turnstile token is single-use and valid for 300 seconds:
// verifying first would burn the token on a submission that then fails a length
// check, and the applicant would have to solve the challenge again to fix a typo.
// The field rules are already published in the frontend, so checking them first
// discloses nothing.
//
// The occupancy queries are the real disclosure surface — they answer "does this
// email or student ID already have an account" — so they stay behind the captcha
// and the rate limiter, where an unverified caller cannot reach them.
func (s Service) Submit(ctx context.Context, input SubmitInput) (*SubmitResult, error) {
	validated, err := validateSubmit(input)
	if err != nil {
		s.auditSubmit(ctx, input, 0, false, errorCode(err), attemptedSubmitDetail(input))
		return nil, err
	}

	if s.Captcha == nil {
		// A nil verifier is a wiring mistake, and the safe reading of it is that no
		// verification happened. Refusing keeps the invariant that this endpoint never
		// accepts an unverified submission.
		unavailable := newError(ErrUnavailable, "申请通道暂不可用，请稍后再试", nil)
		s.auditSubmit(ctx, input, 0, false, errorCode(unavailable), attemptedSubmitDetail(input))
		return nil, unavailable
	}
	if err := s.Captcha.Verify(ctx, input.CaptchaToken, input.ClientIP); err != nil {
		mapped := mapCaptchaError(err)
		s.auditSubmit(ctx, input, 0, false, errorCode(mapped), attemptedSubmitDetail(input))
		return nil, mapped
	}

	// Two buckets: the IP bound stops one host from flooding the queue, and the
	// student-ID bound stops a distributed retry loop from doing it under one
	// identity.
	for _, subject := range []string{"ip:" + input.ClientIP, "student:" + validated.studentID} {
		if err := s.checkLimit(ctx, subject); err != nil {
			s.auditSubmit(ctx, input, 0, false, errorCode(err), attemptedSubmitDetail(input))
			return nil, err
		}
	}

	if err := s.checkOccupancy(ctx, validated); err != nil {
		s.auditSubmit(ctx, input, 0, false, errorCode(err), attemptedSubmitDetail(input))
		return nil, err
	}

	request := &model.AlumniRequest{
		Name:           validated.name,
		StudentID:      validated.studentID,
		LoginEmail:     validated.loginEmail,
		PersonalEmail:  validated.personalEmail,
		PhoneNumber:    validated.phoneNumber,
		QQNumber:       validated.qqNumber,
		College:        validated.college,
		Major:          validated.major,
		JoinYear:       validated.joinYear,
		DepartmentNote: validated.departmentNote,
		Note:           validated.note,
		Status:         model.AlumniRequestStatusPending,
		ClientIP:       input.ClientIP,
	}
	if err := s.Requests.Create(ctx, request); err != nil {
		mapped := s.mapCreateError(ctx, err)
		s.auditSubmit(ctx, input, 0, false, errorCode(mapped), attemptedSubmitDetail(input))
		return nil, mapped
	}

	detail := map[string]any{
		"student_id":     request.StudentID,
		"login_email":    request.LoginEmail,
		"personal_email": request.PersonalEmail,
		// Recorded so a later dispute can establish that the submission did pass
		// verification, rather than leaving it to inference from the absence of a
		// failure row.
		"captcha": "passed",
	}
	s.auditSubmit(ctx, input, request.ID, true, 0, detail)

	return &SubmitResult{RequestID: request.ID}, nil
}

// checkOccupancy refuses a submission whose identifiers already belong to an
// account.
//
// Pre-checked rather than left to the approval transaction because the applicant
// is the only one who can fix it, and they are gone by review time. A collision
// discovered at approval leaves the reviewer holding a ticket they cannot act on
// and no way to reach the person who filled it in.
func (s Service) checkOccupancy(ctx context.Context, validated validatedSubmit) error {
	occupied, err := s.Users.ExistsAsEmailAnywhere(ctx, validated.personalEmail)
	if err != nil {
		return internalError(ctx, "check alumni request email occupancy",
			"查询邮箱占用情况失败", err)
	}
	if occupied {
		return newError(ErrEmailOccupied, "邮箱已被占用", nil)
	}

	// The login email is checked the same way: it becomes the account's login
	// identity, and V005's triggers also forbid it from already existing as an
	// other_mail binding on someone else's account.
	occupied, err = s.Users.ExistsAsEmailAnywhere(ctx, validated.loginEmail)
	if err != nil {
		return internalError(ctx, "check alumni request login email occupancy",
			"查询邮箱占用情况失败", err)
	}
	if occupied {
		return newError(ErrEmailOccupied, "邮箱已被占用", nil)
	}

	exists, err := s.Users.ExistsByStudentID(ctx, validated.studentID)
	if err != nil {
		return internalError(ctx, "check alumni request student id occupancy",
			"查询学号占用情况失败", err)
	}
	if exists {
		return newError(ErrStudentIDOccupied, "学号已被占用", nil)
	}
	return nil
}

// mapCreateError classifies an insert failure.
//
// The pending-student index is the expected one: the applicant submitted twice.
// Everything else is logged rather than guessed at, because reporting the wrong
// cause on an anonymous endpoint gives the submitter no way to make progress.
func (s Service) mapCreateError(ctx context.Context, err error) error {
	if repository.DuplicateConstraint(err) == pendingStudentConstraint {
		return newError(ErrPending, "该学号已有待审申请，请等待处理", err)
	}
	return internalError(ctx, "create alumni request", "提交申请失败", err)
}

// attemptedSubmitDetail records the identifiers from a submission attempt.
//
// The captcha token is deliberately absent: it is a bearer value for the
// verification, and one-time or not it has no place in a durable log.
func attemptedSubmitDetail(input SubmitInput) map[string]any {
	return map[string]any{
		"student_id":     input.StudentID,
		"login_email":    input.LoginEmail,
		"personal_email": input.PersonalEmail,
	}
}

// auditSubmit records a submission attempt with no acting user: the endpoint is
// unauthenticated, so user_id stays NULL rather than being attributed to the
// account the ticket refers to — that account does not exist yet, and the
// submitter's identity is exactly what has not been established.
func (s Service) auditSubmit(
	ctx context.Context,
	input SubmitInput,
	requestID int64,
	success bool,
	errCode int,
	detail map[string]any,
) {
	resourceID := ""
	if requestID != 0 {
		resourceID = formatID(requestID)
	}
	s.audit(ctx, auditParams{
		Action:     actionSubmit,
		Resource:   auditResourceRequest,
		ResourceID: resourceID,
		Success:    success,
		ErrCode:    errCode,
		ClientIP:   input.ClientIP,
		UserAgent:  input.UserAgent,
		Detail:     detail,
	})
}
