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

// Approve provisions the account and records the verdict in one transaction.
//
// The password is generated and hashed here, then discarded: the plaintext never
// leaves this function, is not returned, not emailed and not audited. The alumnus
// sets their own through the password-reset flow, which works because the reset
// lookup accepts a bound other_mail identity — the personal email this ticket
// carries.
//
// Two audit rows, not one. The approval itself is recorded against the ticket, and
// the account creation is recorded against the user, because approval does not go
// through adminuser.CreateUser and that is what would otherwise write it. Without
// the second row the audit trail contains an account nobody appears to have
// created.
func (s Service) Approve(ctx context.Context, input ReviewInput) (*ApproveResult, error) {
	if input.AdminUserID <= 0 {
		return nil, newError(ErrInvalidInput, "缺少审批人信息", nil)
	}

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
	// The account-creation row names the user as its resource and the ticket as its
	// provenance, so a reader of the user's audit history can see where the account
	// came from without joining anything.
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

// buildAccount maps a locked ticket onto the rows to insert.
//
// Runs inside the approval transaction, so it must not perform its own database
// work: the hash is CPU-bound and the repository does the writing. Argon2id at
// the configured cost holds the ticket's row lock for the duration, which is
// acceptable because the lock only contends with a second reviewer acting on the
// same ticket.
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
		// A graduated member: member role, retired_sast state. Both are the console's
		// provisioning defaults, and neither is taken from the submission — a ticket
		// must not be able to ask for a role.
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

// ResendNotification re-queues the result email for a reviewed ticket.
//
// Exists because the delivery path is a bounded queue plus SMTP, and both can
// fail after the review has committed. The approval email is the applicant's only
// instruction to go and set a password, so a lost one leaves a usable account
// nobody can sign in to.
//
// Deliberately allowed even when notified_at is already set: an administrator
// asking for a resend has information the system does not, usually that the
// applicant never received it.
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
// the queue.
//
// Never an error: the review has already committed, and failing the response
// because a channel was full would tell the reviewer their action did not happen
// when it did. A false answer routes them to the resend endpoint instead.
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

// mapReviewError translates an approve or reject failure.
//
// ErrStateConflict is what the row lock produces for a ticket that already
// carries a verdict — the second half of a double-clicked approve. It is reported
// as such rather than as a generic conflict so the console can say "already
// handled" instead of implying the reviewer did something wrong.
//
// A unique violation reaching here means the pre-submission occupancy check lost
// a race with a registration: the ticket was clean when it was filed and the
// account appeared in between. The reviewer needs to know which field, hence the
// constraint-name classification rather than a generic conflict.
func (s Service) mapReviewError(ctx context.Context, err error, message string) error {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return newError(ErrNotFound, "建号申请不存在", err)
	case errors.Is(err, repository.ErrStateConflict):
		return newError(ErrAlreadyReviewed, "该申请已被处理", err)
	}
	// A typed error from the provision callback travels back unchanged: it was
	// already classified (hash failure, password generation) and re-wrapping would
	// bury an internal cause under a conflict message.
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
