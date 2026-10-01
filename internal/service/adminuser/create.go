package adminuser

import (
	"context"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// CreateUser creates an account and optionally binds a personal email as an
// other_mail identity in the same transaction. The initial password is generated
// because the member is not present to enter one, and the plaintext is returned in
// CreateUserResult but never persisted or audited.
func (s Service) CreateUser(ctx context.Context, input CreateUserInput) (*CreateUserResult, error) {
	validated, err := validateCreate(input, s.now())
	if err != nil {
		s.auditCreate(ctx, input, 0, false, errorCode(err), attemptedCreateDetail(input))
		return nil, err
	}
	// The manager boundary on the provision path: creating an account is a write,
	// and a manager's writes stop short of the admin role. The default (member)
	// and every other role are within its reach.
	if !callerIsAdmin(input.AdminRole) && validated.role == model.UserRoleAdmin {
		refused := newError(ErrProtected, "不可授予 admin 角色", nil)
		s.auditCreate(ctx, input, 0, false, errorCode(refused), attemptedCreateDetail(input))
		return nil, refused
	}

	// The NJUPT-prefix collision guard: a login_email whose prefix names another
	// account's student ID hands that student a reset handle on the new account
	// (the reset flow resolves by identifier and delivers to that mailbox), so the
	// prefix is looked up whenever it is not the submitted student ID itself.
	if prefix, lookup := validate.UnmatchedNjuptPrefix(validated.loginEmail, validated.studentID); lookup {
		taken, prefixErr := s.Users.ExistsByStudentIDExcluding(ctx, prefix, 0)
		if prefixErr != nil {
			internalErr := newError(ErrInternal, "查询邮箱前缀占用情况失败", prefixErr)
			s.auditCreate(ctx, input, 0, false, errorCode(internalErr), attemptedCreateDetail(input))
			return nil, internalErr
		}
		if taken {
			occupiedErr := newError(ErrStudentIDOccupied, "login_email 前缀与其他账号学号冲突", nil)
			s.auditCreate(ctx, input, 0, false, errorCode(occupiedErr), attemptedCreateDetail(input))
			return nil, occupiedErr
		}
	}

	var boundEmail *string
	if validated.personalEmail != nil {
		// A bound personal email becomes a login handle and a reset target, so it must
		// not already belong to another account; the pre-check stops the unique indexes
		// and V005 trigger from racing.
		boundEmail = validated.personalEmail
		occupied, existsErr := s.Users.ExistsAsEmailAnywhere(ctx, *validated.personalEmail)
		if existsErr != nil {
			internalErr := newError(ErrInternal, "查询邮箱占用情况失败", existsErr)
			s.auditCreate(ctx, input, 0, false, errorCode(internalErr), attemptedCreateDetail(input))
			return nil, internalErr
		}
		if occupied {
			occupiedErr := newError(ErrEmailOccupied, "邮箱已被占用", nil)
			s.auditCreate(ctx, input, 0, false, errorCode(occupiedErr), attemptedCreateDetail(input))
			return nil, occupiedErr
		}
	}

	password, err := auth.GenerateInitialPassword()
	if err != nil {
		internalErr := newError(ErrInternal, "生成初始密码失败", err)
		s.auditCreate(ctx, input, 0, false, errorCode(internalErr), attemptedCreateDetail(input))
		return nil, internalErr
	}
	hash, err := s.Passwords.HashPassword(ctx, password)
	if err != nil {
		internalErr := newError(ErrInternal, "生成密码哈希失败", err)
		s.auditCreate(ctx, input, 0, false, errorCode(internalErr), attemptedCreateDetail(input))
		return nil, internalErr
	}

	user := &model.User{
		Role:         validated.role,
		Name:         validated.name,
		PhoneNumber:  validated.phoneNumber,
		QQNumber:     validated.qqNumber,
		StudentID:    validated.studentID,
		State:        validated.state,
		StateManual:  validated.stateManual,
		LoginEmail:   validated.loginEmail,
		College:      validated.college,
		Major:        validated.major,
		PasswordHash: hash,
	}
	// The admin binding follows the same shape as self-service: identity_data is
	// empty because provider_id stores the email.
	var identity *model.Identity
	if boundEmail != nil {
		identity = &model.Identity{
			Provider:   model.LoginMethodOtherMail,
			ProviderID: *boundEmail,
		}
	}
	if err := s.Users.CreateAdminUser(ctx, user, &model.Profile{}, identity); err != nil {
		mapped := s.mapUniqueViolation(ctx, err, "新建用户失败")
		s.auditCreate(ctx, input, 0, false, errorCode(mapped), attemptedCreateDetail(input))
		return nil, mapped
	}

	detail := map[string]any{
		"login_email": user.LoginEmail,
		"role":        string(user.Role),
		"state":       string(user.State),
	}
	if identity != nil {
		detail["bound_email"] = identity.ProviderID
	}
	s.auditCreate(ctx, input, user.ID, true, 0, detail)

	return &CreateUserResult{
		UserID:          user.ID,
		LoginEmail:      user.LoginEmail,
		InitialPassword: password,
	}, nil
}

// attemptedCreateDetail records the identifiers from a failed provision. It
// never includes the initial password.
func attemptedCreateDetail(input CreateUserInput) map[string]any {
	detail := map[string]any{"login_email": input.LoginEmail}
	if input.PersonalEmail != nil {
		detail["attempted_personal_email"] = *input.PersonalEmail
	}
	return detail
}

// auditCreate records a provisioning attempt. On failure the account does not
// exist yet, so TargetUserID is 0 and the detail records the attempted login
// email.
func (s Service) auditCreate(
	ctx context.Context,
	input CreateUserInput,
	userID int64,
	success bool,
	errCode int,
	detail map[string]any,
) {
	s.audit(ctx, auditParams{
		AdminUserID:   input.AdminUserID,
		ActorClientID: input.ActorClientID,
		Action:        actionCreateUser,
		TargetUserID:  userID,
		Success:       success,
		ErrCode:       errCode,
		ClientIP:      input.ClientIP,
		UserAgent:     input.UserAgent,
		Detail:        detail,
	})
}
