package alumnirequest

import (
	"context"
	"errors"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// List returns a page of tickets for the reviewer's queue.
func (s Service) List(ctx context.Context, input ListInput) (*ListResult, error) {
	status, err := parseStatus(input.Status)
	if err != nil {
		return nil, err
	}
	page, pageSize := resolvePaging(input.Page, input.PageSize)

	keyword := input.Keyword
	if !validKeyword(keyword) {
		return nil, newError(ErrInvalidInput, "keyword 长度超出限制", nil)
	}

	rows, total, err := s.Requests.List(ctx, repository.AlumniRequestFilter{
		Status:   status,
		Notified: input.Notified,
		Keyword:  keyword,
		Limit:    pageSize,
		Offset:   (page - 1) * pageSize,
	})
	if err != nil {
		return nil, internalError(ctx, "list alumni requests", "查询建号申请失败", err)
	}

	// Always a slice, never nil: a nil marshals to JSON null and clients that
	// iterate the field would have to special-case an empty queue.
	views := make([]RequestView, 0, len(rows))
	for _, row := range rows {
		views = append(views, requestView(row))
	}
	return &ListResult{Requests: views, Total: total, Page: page, PageSize: pageSize}, nil
}

// Get returns one ticket.
func (s Service) Get(ctx context.Context, requestID int64) (*RequestView, error) {
	request, err := s.Requests.Get(ctx, requestID)
	if err != nil {
		return nil, s.mapLookupError(ctx, err)
	}
	view := requestView(*request)
	return &view, nil
}

// Approve executes the verdict a ticket's intent calls for: provisioning for a
// provision ticket (the V011 path), access restoration for a recovery one. The
// intent is read here, from the stored ticket, before either repository method
// runs — intent is written once at submission and never mutated, so a pre-lock
// read cannot disagree with what the locked transaction will see.
func (s Service) Approve(ctx context.Context, input ReviewInput) (*ApproveResult, error) {
	if input.AdminUserID <= 0 {
		return nil, newError(ErrInvalidInput, "缺少审批人信息", nil)
	}

	ticket, err := s.Requests.Get(ctx, input.RequestID)
	if err != nil {
		mapped := s.mapLookupError(ctx, err)
		s.auditReview(ctx, input, actionApprove, false, errorCode(mapped), nil)
		return nil, mapped
	}
	if ticket.Intent == model.AlumniRequestIntentRecover {
		return s.approveRecover(ctx, input)
	}
	return s.approveProvision(ctx, input)
}

// approveProvision is the original approval: mint an account with a discarded
// password and a retired_sast state.
func (s Service) approveProvision(ctx context.Context, input ReviewInput) (*ApproveResult, error) {
	var provisioned *model.User
	approved, err := s.Requests.ApproveAlumniRequest(ctx, input.RequestID, input.AdminUserID, s.now(),
		func(request *model.AlumniRequest) (*model.User, *model.Profile, *model.Identity, error) {
			user, profile, identity, buildErr := s.buildAccount(ctx, request)
			if buildErr != nil {
				return nil, nil, nil, buildErr
			}
			provisioned = user
			return user, profile, identity, nil
		})
	if err != nil {
		mapped := s.mapReviewError(ctx, err, "审批失败")
		s.auditReview(ctx, input, actionApprove, false, errorCode(mapped), nil)
		return nil, mapped
	}

	s.auditReview(ctx, input, actionApprove, true, 0, map[string]any{
		"student_id":  approved.StudentID,
		"login_email": approved.LoginEmail,
		"user_id":     provisioned.ID,
	})
	// The account-creation row names the ticket as provenance, so a reader of the
	// user's audit history can see where the account came from without joining
	// anything.
	s.auditAccountCreation(ctx, input, provisioned, approved)

	enqueued := s.enqueueNotification(NotificationJob{
		RequestID: approved.ID,
		Recipient: approved.PersonalEmail,
		Name:      approved.Name,
		Approved:  true,
	})

	return &ApproveResult{
		UserID:         provisioned.ID,
		LoginEmail:     approved.LoginEmail,
		NotifyEnqueued: enqueued,
	}, nil
}

// approveRecover binds the ticket's personal email onto the account the student
// ID already names, restoring a way in. One audit row carries recovered, the
// target and the bound address: no admin_user_create line — nothing was created,
// and writing one would put an uncreated account into the trail. The generated
// password machinery is never touched, so there is no credential to discard.
func (s Service) approveRecover(ctx context.Context, input ReviewInput) (*ApproveResult, error) {
	approved, err := s.Requests.ApproveAlumniRequestRecover(ctx, input.RequestID, input.AdminUserID, s.now())
	if err != nil {
		mapped := s.mapReviewError(ctx, err, "审批失败")
		s.auditReview(ctx, input, actionApprove, false, errorCode(mapped), nil)
		return nil, mapped
	}

	target := *approved.CreatedUserID
	s.auditReview(ctx, input, actionApprove, true, 0, map[string]any{
		"recovered":      true,
		"student_id":     approved.StudentID,
		"login_email":    approved.LoginEmail,
		"target_user_id": target,
		"bound_email":    approved.PersonalEmail,
	})

	enqueued := s.enqueueNotification(NotificationJob{
		RequestID: approved.ID,
		Recipient: approved.PersonalEmail,
		Name:      approved.Name,
		Approved:  true,
		Recovered: true,
	})

	return &ApproveResult{
		UserID:         target,
		LoginEmail:     approved.LoginEmail,
		NotifyEnqueued: enqueued,
	}, nil
}

// buildAccount maps a locked ticket onto the rows to insert. It runs inside the
// approval transaction, so it must not perform its own database work; the argon2id
// hash holds the ticket row lock only long enough to contend with a second review
// of the same ticket.
func (s Service) buildAccount(
	ctx context.Context,
	request *model.AlumniRequest,
) (*model.User, *model.Profile, *model.Identity, error) {
	password, err := auth.GenerateInitialPassword()
	if err != nil {
		return nil, nil, nil, internalError(ctx, "generate alumni initial password",
			"生成初始密码失败", err)
	}
	hash, err := s.Passwords.HashPassword(ctx, password)
	if err != nil {
		return nil, nil, nil, internalError(ctx, "hash alumni initial password",
			"生成密码哈希失败", err)
	}

	user := &model.User{
		// Member role and retired_sast state, both the console's provisioning defaults
		// and never taken from the submission — a ticket must not be able to ask for
		// a role.
		Role:         model.UserRoleMember,
		State:        model.UserStateRetiredSAST,
		Name:         request.Name,
		PhoneNumber:  request.PhoneNumber,
		QQNumber:     request.QQNumber,
		StudentID:    request.StudentID,
		LoginEmail:   request.LoginEmail,
		College:      request.College,
		Major:        request.Major,
		PasswordHash: hash,
	}
	// The binding follows the console's shape: identity_data is empty because
	// provider_id stores the address.
	identity := &model.Identity{
		Provider:   model.LoginMethodOtherMail,
		ProviderID: request.PersonalEmail,
	}
	return user, &model.Profile{}, identity, nil
}

// Reject records a rejection and notifies the applicant.
//
// The reason is mandatory because it reaches them by email and is the only thing
// that tells them what to correct before resubmitting.
func (s Service) Reject(ctx context.Context, input ReviewInput) (*ReviewResult, error) {
	if input.AdminUserID <= 0 {
		return nil, newError(ErrInvalidInput, "缺少审批人信息", nil)
	}
	reason, err := validateRejectReason(input.Reason)
	if err != nil {
		s.auditReview(ctx, input, actionReject, false, errorCode(err), nil)
		return nil, err
	}

	rejected, err := s.Requests.RejectAlumniRequest(ctx, input.RequestID, input.AdminUserID, reason, s.now())
	if err != nil {
		mapped := s.mapReviewError(ctx, err, "驳回失败")
		s.auditReview(ctx, input, actionReject, false, errorCode(mapped), nil)
		return nil, mapped
	}

	s.auditReview(ctx, input, actionReject, true, 0, map[string]any{
		"student_id": rejected.StudentID,
	})

	enqueued := s.enqueueNotification(NotificationJob{
		RequestID:    rejected.ID,
		Recipient:    rejected.PersonalEmail,
		Name:         rejected.Name,
		Approved:     false,
		RejectReason: rejected.RejectReason,
	})
	return &ReviewResult{NotifyEnqueued: enqueued}, nil
}

// ResendNotification re-queues the result email for a reviewed ticket; the
// delivery path is a bounded queue plus SMTP, and both can fail after the review
// has committed. The approval email is the applicant's only instruction to set a
// password, so a lost one leaves a usable account nobody can sign in to. Allowed
// even when notified_at is already set, since an administrator asking for a resend
// knows something the system does not.
func (s Service) ResendNotification(ctx context.Context, input ReviewInput) (*ReviewResult, error) {
	request, err := s.Requests.Get(ctx, input.RequestID)
	if err != nil {
		mapped := s.mapLookupError(ctx, err)
		s.auditReview(ctx, input, actionResendNotification, false, errorCode(mapped), nil)
		return nil, mapped
	}
	if request.Status == model.AlumniRequestStatusPending {
		notReviewed := newError(ErrNotReviewed, "该申请尚未处理，无结果可通知", nil)
		s.auditReview(ctx, input, actionResendNotification, false, errorCode(notReviewed), nil)
		return nil, notReviewed
	}

	enqueued := s.enqueueNotification(NotificationJob{
		RequestID:    request.ID,
		Recipient:    request.PersonalEmail,
		Name:         request.Name,
		Approved:     request.Status == model.AlumniRequestStatusApproved,
		RejectReason: request.RejectReason,
	})
	s.auditReview(ctx, input, actionResendNotification, true, 0, map[string]any{
		"notify_enqueued": enqueued,
	})
	return &ReviewResult{NotifyEnqueued: enqueued}, nil
}

// enqueueNotification hands the email to the worker, reporting whether it fit in
// the queue. Never an error: the review has already committed, so a false answer
// routes the reviewer to the resend endpoint.
func (s Service) enqueueNotification(job NotificationJob) bool {
	if s.Notifier == nil {
		return false
	}
	return s.Notifier.EnqueueAlumniNotification(job)
}

// mapLookupError translates a Get failure.
func (s Service) mapLookupError(ctx context.Context, err error) error {
	if errors.Is(err, repository.ErrNotFound) {
		return newError(ErrNotFound, "建号申请不存在", err)
	}
	return internalError(ctx, "get alumni request", "查询建号申请失败", err)
}

// mapReviewError translates an approve or reject failure. ErrStateConflict is what
// the row lock produces for a second verdict (the second half of a double-clicked
// approve). A unique violation reaching here means the pre-submission occupancy
// check lost a race with a registration, so the constraint name tells the reviewer
// which field.
func (s Service) mapReviewError(ctx context.Context, err error, message string) error {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return newError(ErrNotFound, "建号申请不存在", err)
	case errors.Is(err, repository.ErrStateConflict):
		return newError(ErrAlreadyReviewed, "该申请已被处理", err)
	case errors.Is(err, repository.ErrStudentIDExists):
		return newError(ErrStudentIDOccupied, "学号已被占用", err)
	case errors.Is(err, repository.ErrRecoverTargetMissing):
		return newError(ErrTargetVanished, "该学号当前没有对应账号，请刷新后核对工单", err)
	case errors.Is(err, repository.ErrAccountClosed):
		return newError(ErrAccountClosedForRecover, "该学号的账号已注销，无法恢复访问方式", err)
	case errors.Is(err, repository.ErrLoginEmailMismatch):
		return newError(ErrStaleRecoverTicket,
			"工单中的 login_email 与该学号现有账号的登录邮箱不一致，请驳回后由申请人重新提交", err)
	case errors.Is(err, repository.ErrIdentityLimitExceeded):
		return newError(ErrIdentityLimitReached, "该账号的邮箱绑定数量已达上限", err)
	}
	// A typed error from the provision callback is already classified and travels
	// back unchanged.
	var typed *Error
	if errors.As(err, &typed) {
		return err
	}
	switch repository.DuplicateConstraint(err) {
	case "user_login_email_key", "ck_user_login_email_not_identity",
		"ck_identities_provider_id_not_login_email", "uq_identities_provider_provider_id":
		return newError(ErrEmailOccupied, "邮箱已被占用", err)
	case "user_student_id_key":
		return newError(ErrStudentIDOccupied, "学号已被占用", err)
	}
	return internalError(ctx, "review alumni request", message, err)
}

// auditReview records a review action against the ticket.
func (s Service) auditReview(
	ctx context.Context,
	input ReviewInput,
	action string,
	success bool,
	errCode int,
	detail map[string]any,
) {
	reviewer := input.AdminUserID
	s.audit(ctx, auditParams{
		UserID:        &reviewer,
		ActorClientID: input.ActorClientID,
		Action:        action,
		Resource:      auditResourceRequest,
		ResourceID:    formatID(input.RequestID),
		Success:       success,
		ErrCode:       errCode,
		ClientIP:      input.ClientIP,
		UserAgent:     input.UserAgent,
		Detail:        detail,
	})
}

// auditAccountCreation records the provisioning itself, so the account appears in
// the audit trail with the ticket it came from.
func (s Service) auditAccountCreation(
	ctx context.Context,
	input ReviewInput,
	user *model.User,
	request *model.AlumniRequest,
) {
	reviewer := input.AdminUserID
	s.audit(ctx, auditParams{
		UserID:        &reviewer,
		ActorClientID: input.ActorClientID,
		Action:        actionCreateUser,
		Resource:      auditResourceUser,
		ResourceID:    formatID(user.ID),
		Success:       true,
		ClientIP:      input.ClientIP,
		UserAgent:     input.UserAgent,
		Detail: map[string]any{
			"login_email": user.LoginEmail,
			"role":        string(user.Role),
			"state":       string(user.State),
			"bound_email": request.PersonalEmail,
			// Marks the provenance so this row is distinguishable from a console
			// provisioning of the same shape.
			"via":               auditResourceRequest,
			"alumni_request_id": request.ID,
		},
	})
}

// validKeyword bounds the search term. Same ceiling the console list uses, since
// it is the same column set being matched.
func validKeyword(keyword string) bool {
	return len(keyword) <= 255
}
