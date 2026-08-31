package alumnirequest

import (
	"context"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// pendingStudentConstraint is V011's partial unique index: one open ticket per
// student ID.
const pendingStudentConstraint = "uq_alumni_requests_pending_student"

// Submit records an account-request ticket. Field validation runs before the
// captcha, because a Turnstile token is single-use and short-lived: verifying
// first would burn it on a submission that then fails a length check. The
// occupancy queries — the real disclosure surface ("does this email or student ID
// already have an account") — run behind both the captcha and the rate limiter.
func (s Service) Submit(ctx context.Context, input SubmitInput) (*SubmitResult, error) {
	validated, err := validateSubmit(input)
	if err != nil {
		s.auditSubmit(ctx, input, 0, false, errorCode(err), attemptedSubmitDetail(input))
		return nil, err
	}

	if s.Captcha == nil {
		// A nil verifier means no verification happened; refusing keeps this endpoint
		// from ever accepting an unverified submission.
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
		Intent:         validated.intent,
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
		"intent":         string(request.Intent),
		// Recorded so a later dispute can establish that the submission did pass
		// verification.
		"captcha": "passed",
	}
	s.auditSubmit(ctx, input, request.ID, true, 0, detail)

	return &SubmitResult{RequestID: request.ID}, nil
}

// checkOccupancy refuses a submission whose identifiers are in the wrong
// relationship to the database. Both intents share the personal-email guards;
// the student-ID direction is what they flip on:
//
//   - provision requires the ID to be free (the account would collide with it);
//   - recover requires the ID to resolve to an existing account, and its login
//     email to match the ticket's — that pairing is what makes approval touch
//     one specific account instead of whichever row happens to be closest.
func (s Service) checkOccupancy(ctx context.Context, v validatedSubmit) error {
	if v.intent == model.AlumniRequestIntentRecover {
		registeredLoginEmail, found, err := s.Users.FindLoginEmailByStudentID(ctx, v.studentID)
		if err != nil {
			return internalError(ctx, "resolve recovery target",
				"查询学号对应账号失败", err)
		}
		if !found {
			return newError(ErrRecoverNoTarget,
				"该学号尚无账号，如需新开账号请使用普通申请", nil)
		}
		if registeredLoginEmail != v.loginEmail {
			return newError(ErrLoginEmailMismatch,
				"login_email 与该学号登记的登录邮箱不一致", nil)
		}
	} else {
		occupied, err := s.Users.ExistsAsEmailAnywhere(ctx, v.loginEmail)
		if err != nil {
			return internalError(ctx, "check alumni request login email occupancy",
				"查询邮箱占用情况失败", err)
		}
		if occupied {
			return newError(ErrEmailOccupied, "邮箱已被占用", nil)
		}
		_, found, err := s.Users.FindLoginEmailByStudentID(ctx, v.studentID)
		if err != nil {
			return internalError(ctx, "check alumni request student id occupancy",
				"查询学号占用情况失败", err)
		}
		if found {
			// The applicant is likely the owner of that account: a graduated member
			// whose school mailbox died does not need a second account, they need
			// access restored to the first. Point them back at this same flow; the
			// support address stays for when the form itself will not load.
			return newError(ErrStudentIDOccupied,
				"该学号已有账号。若这是您本人且无法登录（如毕业邮箱已停用），可在本页切换为「恢复已有账号访问」重新提交，或联系 link@sast.fun", nil)
		}
	}

	// A pending ticket is not an account, so the checks above cannot see it; the
	// first approval would bind the address and leave every later ticket stuck,
	// so refuse the overlap up front. Shared by both intents.
	pending, err := s.Requests.EmailHasPendingTicket(ctx, v.personalEmail)
	if err != nil {
		return internalError(ctx, "check alumni request pending email",
			"查询待审申请失败", err)
	}
	if pending {
		return newError(ErrEmailPending, "该邮箱已有待审申请，请等待处理", nil)
	}
	occupied, err := s.Users.ExistsAsEmailAnywhere(ctx, v.personalEmail)
	if err != nil {
		return internalError(ctx, "check alumni request email occupancy",
			"查询邮箱占用情况失败", err)
	}
	if occupied {
		return newError(ErrEmailOccupied, "邮箱已被占用", nil)
	}
	return nil
}

// mapCreateError classifies an insert failure. The pending-student index means the
// applicant submitted twice; anything else is logged rather than guessed, since the
// wrong cause on an anonymous endpoint gives the submitter no way to make progress.
func (s Service) mapCreateError(ctx context.Context, err error) error {
	if repository.DuplicateConstraint(err) == pendingStudentConstraint {
		return newError(ErrPending, "该学号已有待审申请，请等待处理", err)
	}
	return internalError(ctx, "create alumni request", "提交申请失败", err)
}

// attemptedSubmitDetail records the identifiers from a submission attempt. The
// captcha token is deliberately absent: it is a bearer value with no place in a
// durable log.
func attemptedSubmitDetail(input SubmitInput) map[string]any {
	return map[string]any{
		"student_id":     input.StudentID,
		"login_email":    input.LoginEmail,
		"personal_email": input.PersonalEmail,
	}
}

// auditSubmit records a submission attempt with no acting user: the endpoint is
// unauthenticated, so user_id stays NULL.
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
