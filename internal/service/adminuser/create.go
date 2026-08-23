package adminuser

import (
	"context"
	"crypto/rand"
	"encoding/base64"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// initialPasswordBytes is the entropy behind the generated first password.
// 24 random bytes encoded as raw base64url produce a 32-character credential of
// mixed case, digits and URL-safe symbols — beyond practical guessing even if a
// leaked hash sample were to constrain the salt. Nobody, including the
// administrator, knows or chooses it except for the single response that
// carries it.
const initialPasswordBytes = 24

// generateInitialPassword returns a fresh unguessable first password. base64url
// keeps it free of characters a frontend would need to escape or a user would
// misread while being relayed out of band.
func generateInitialPassword() (string, error) {
	buffer := make([]byte, initialPasswordBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// CreateUser provisions a fresh account, optionally binding a personal email as
// an other_mail login identity inside the same transaction.
//
// The initial password is generated rather than taken from the request: the
// member is not present to type one, and a credential the administrator chooses
// is a credential only one person chose. The plaintext leaves in
// CreateUserResult and is never persisted or audited.
func (s Service) CreateUser(ctx context.Context, input CreateUserInput) (*CreateUserResult, error) {
	validated, err := validateCreate(input)
	if err != nil {
		s.auditCreate(ctx, input, 0, false, errorCode(err), attemptedCreateDetail(input))
		return nil, err
	}

	var boundEmail *string
	if validated.personalEmail != nil {
		// A bound personal email is both a login handle (FindAuthUserByLoginIdentifier
		// already resolves other_mail identities) and the account's password-reset
		// channel once bound, so it must not already serve another account. The
		// pre-check maps a collision to ErrEmailOccupied before the unique indexes —
		// and V005, which forbids an address doubling as somebody's login email —
		// race it into a constraint error.
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

	password, err := generateInitialPassword()
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
		LoginEmail:   validated.loginEmail,
		College:      validated.college,
		Major:        validated.major,
		PasswordHash: hash,
	}
	// An admin-vouched binding mirrors the self-service bind path, whose identity
	// row carries no identity_data — provider_id already holds the email.
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

// attemptedCreateDetail names what a failed provision was trying to create. An
// identifier only — the plaintext initial password never enters the audit trail,
// and the response is the only place it exists.
func attemptedCreateDetail(input CreateUserInput) map[string]any {
	detail := map[string]any{"login_email": input.LoginEmail}
	if input.PersonalEmail != nil {
		detail["attempted_personal_email"] = *input.PersonalEmail
	}
	return detail
}

// auditCreate records a provisioning attempt, success or failure. A failed
// provision has no account to name, so TargetUserID stays 0 and the detail
// names the login email that was attempted (an identifier, never a credential)
// so an attempted collision stays attributable.
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
