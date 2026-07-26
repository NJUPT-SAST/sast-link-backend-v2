package session

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/mailer"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

const (
	defaultAccessTTL         = time.Hour
	defaultRefreshTTL        = 30 * 24 * time.Hour
	loginCompensationTimeout = 5 * time.Second
	// verificationTTL bounds email verification codes and the tickets derived
	// from them (Register-Ticket / Bind-Ticket), per the API contract's 5-minute
	// one-time semantics.
	verificationTTL = 5 * time.Minute
	// maxOtherMailBindings is the per-user cap on other_mail identities.
	maxOtherMailBindings = 2
)

var sessionScopes = scope.InternalSessionScopes

type Service struct {
	Users            UserRepository
	Clients          ClientRepository
	Tokens           TokenRepository
	Audit            AuditRepository
	Identities       IdentityRepository
	Limiter          EndpointLimiter
	EmailLimiter     EndpointLimiter
	EmailIPLimiter   EndpointLimiter
	Failures         LoginFailureStore
	Blacklist        TokenBlacklist
	Mailer           Mailer
	VerificationCode VerificationCodeStore
	RegisterTicket   RegisterTicketStore
	BindTicket       BindTicketStore
	InternalClientID string
	JWT              *auth.JWTManager
	RefreshTokens    *auth.RefreshTokenManager
	Passwords        auth.PasswordHasher
	Clock            Clock
	AccessTTL        time.Duration
	RefreshTTL       time.Duration
}

func (s Service) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	identifier := normalizeIdentifier(input.Identifier)
	if identifier == "" || input.Password == "" {
		return nil, newError(ErrInvalidInput, "invalid login input", nil)
	}
	if err := s.checkEndpointLimit(ctx, "login", loginLimitSubject(input, identifier)); err != nil {
		return nil, err
	}
	client, err := s.findInternalClient(ctx)
	if err != nil {
		return nil, err
	}
	user, err := s.Users.FindByLoginIdentifier(ctx, identifier)
	if errors.Is(err, repository.ErrNotFound) {
		failureKey := loginFailureKey(nil, identifier)
		if lockErr := s.checkLoginLock(ctx, failureKey); lockErr != nil {
			return nil, lockErr
		}
		return nil, s.failLogin(ctx, nil, input, failureKey, ErrUnknownIdentifier, "login identifier not found", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find login user", err)
	}
	failureKey := loginFailureKey(user, identifier)
	if lockErr := s.checkLoginLock(ctx, failureKey); lockErr != nil {
		return nil, lockErr
	}
	if user.State == model.UserStateDeleted {
		if auditErr := s.audit(ctx, &user.ID, "login", "session", nil, false, errcode.CodeAccountDeleted, input.ClientIP, input.UserAgent, map[string]any{"method": loginMethod(user, identifier)}); auditErr != nil {
			slog.Error("audit deleted login failure", "user_id", user.ID, "error", auditErr)
		}
		return nil, newError(ErrUserDeleted, "user is deleted", nil)
	}
	if passwordErr := s.Passwords.VerifyPassword(input.Password, user.PasswordHash); passwordErr != nil {
		return nil, s.failLogin(ctx, user, input, failureKey, ErrPasswordInvalid, "password is invalid", passwordErr)
	}
	pair, err := s.issuePair(user, client, 0, "", sessionScopes)
	if err != nil {
		return nil, err
	}
	if err := s.Tokens.CreatePair(ctx, pair.access, pair.refresh); err != nil {
		return nil, newError(ErrInternal, "create token pair", err)
	}
	// From here the token pair is persisted. Any subsequent failure must
	// compensate by revoking the family so no half-issued session survives.
	compensate := func(message string, cause error) error {
		compensationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), loginCompensationTimeout)
		defer cancel()
		entries, revokeErr := s.Tokens.RevokeFamily(compensationCtx, pair.familyID, s.now())
		if revokeErr != nil {
			slog.Error("compensate revoke after login failure", "family_id", pair.familyID, "error", revokeErr)
		}
		s.deliverBlacklist(compensationCtx, entries, s.now())
		return newError(ErrInternal, message, cause)
	}
	if s.Failures != nil {
		if resetErr := s.Failures.Reset(ctx, failureKey); resetErr != nil {
			// A stale failure counter could lock the user on the next login.
			// Fail closed by revoking the issued pair.
			return nil, compensate("reset login failures", resetErr)
		}
	}
	if auditErr := s.audit(ctx, &user.ID, "login", "session", nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"method": loginMethod(user, identifier)}); auditErr != nil {
		return nil, compensate("audit login success", auditErr)
	}
	return &LoginResult{
		AccessToken:      pair.accessToken,
		RefreshToken:     pair.refreshToken,
		TokenType:        BearerTokenType,
		Scope:            pair.scopeClaim,
		AccessExpiresAt:  pair.access.ExpiresAt,
		RefreshExpiresAt: pair.refresh.ExpiresAt,
		Profile:          profileDTO(user),
	}, nil
}

func (s Service) Refresh(ctx context.Context, input RefreshInput) (*RefreshResult, error) {
	if strings.TrimSpace(input.RefreshToken) == "" {
		return nil, newError(ErrInvalidInput, "invalid refresh input", nil)
	}
	tokenHash, err := s.RefreshTokens.HashRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, newError(ErrInvalidToken, "invalid refresh token", err)
	}
	current, err := s.Tokens.FindRefreshToken(ctx, tokenHash)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "invalid refresh token", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find refresh token", err)
	}
	if current.RevokedAt != nil {
		entries, revokeErr := s.Tokens.RevokeFamily(ctx, current.FamilyID, s.now())
		if revokeErr != nil {
			return nil, newError(ErrInternal, "revoke replayed refresh family", revokeErr)
		}
		s.deliverBlacklist(ctx, entries, s.now())
		return nil, newError(ErrInvalidToken, "invalid refresh token", nil)
	}
	if !current.ExpiresAt.After(s.now()) {
		return nil, newError(ErrInvalidToken, "invalid refresh token", nil)
	}
	client, err := s.findInternalClient(ctx)
	if err != nil {
		return nil, err
	}
	if current.ClientID != client.ID {
		return nil, newError(ErrInvalidToken, "refresh token client mismatch", nil)
	}
	user, err := s.Users.FindByID(ctx, current.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "invalid refresh token user", nil)
	}
	if err == nil && user.State == model.UserStateDeleted {
		return nil, newError(ErrUserDeleted, "user is deleted", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find refresh user", err)
	}

	pair, err := s.issuePair(user, client, current.Sequence+1, current.FamilyID, []string(current.Scopes))
	if err != nil {
		return nil, err
	}
	if rotateErr := s.Tokens.RotateRefreshToken(ctx, tokenHash, pair.access, pair.refresh); rotateErr != nil {
		if errors.Is(rotateErr, repository.ErrTokenReplay) || errors.Is(rotateErr, repository.ErrTokenExpired) || errors.Is(rotateErr, repository.ErrTokenFamilyRevoked) {
			// RotateRefreshToken revokes the family in the repository; re-invoke
			// RevokeFamily to obtain blacklist entries for synchronous Redis delivery.
			entries, revokeErr := s.Tokens.RevokeFamily(ctx, current.FamilyID, s.now())
			if revokeErr != nil {
				return nil, newError(ErrInternal, "revoke refresh family after rotation failure", revokeErr)
			}
			s.deliverBlacklist(ctx, entries, s.now())
			return nil, newError(ErrInvalidToken, "invalid refresh token", rotateErr)
		}
		return nil, newError(ErrInternal, "rotate refresh token", rotateErr)
	}
	return &RefreshResult{
		AccessToken:      pair.accessToken,
		RefreshToken:     pair.refreshToken,
		TokenType:        BearerTokenType,
		Scope:            pair.scopeClaim,
		AccessExpiresAt:  pair.access.ExpiresAt,
		RefreshExpiresAt: pair.refresh.ExpiresAt,
	}, nil
}

func (s Service) Logout(ctx context.Context, input LogoutInput) (*LogoutResult, error) {
	principalJTI := strings.TrimSpace(input.PrincipalJTI)
	if principalJTI == "" || input.PrincipalUserID <= 0 || strings.TrimSpace(input.RefreshToken) == "" {
		return nil, newError(ErrInvalidInput, "invalid logout input", nil)
	}
	access, err := s.Tokens.FindAccessTokenByJTI(ctx, principalJTI)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "access token metadata not found", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find access token", err)
	}
	tokenHash, err := s.RefreshTokens.HashRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, newError(ErrInvalidToken, "invalid refresh token", err)
	}
	refresh, err := s.Tokens.FindRefreshToken(ctx, tokenHash)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "refresh token metadata not found", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find refresh token", err)
	}
	now := s.now()
	if !access.ExpiresAt.After(now) || !refresh.ExpiresAt.After(now) {
		return nil, newError(ErrInvalidToken, "token is expired", nil)
	}
	if access.RevokedAt != nil || refresh.RevokedAt != nil {
		return nil, newError(ErrInvalidToken, "token is revoked", nil)
	}
	if access.FamilyID == nil || *access.FamilyID != refresh.FamilyID || access.UserID != input.PrincipalUserID || refresh.UserID != input.PrincipalUserID || access.ClientID != refresh.ClientID {
		return nil, newError(ErrInvalidToken, "token ownership mismatch", nil)
	}
	familyID := refresh.FamilyID
	entries, revokeErr := s.Tokens.RevokeFamily(ctx, familyID, now)
	if revokeErr != nil {
		return nil, newError(ErrInternal, "revoke token family", revokeErr)
	}
	s.deliverBlacklist(ctx, entries, now)
	if auditErr := s.audit(ctx, &input.PrincipalUserID, "logout", "session", &familyID, true, 0, input.ClientIP, input.UserAgent, map[string]any{}); auditErr != nil {
		slog.Error("audit logout", "family_id", familyID, "error", auditErr)
	}
	return &LogoutResult{BlacklistedJTI: principalJTI, FamilyID: familyID}, nil
}

func (s Service) Profile(ctx context.Context, input ProfileInput) (*ProfileResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidInput, "invalid profile input", nil)
	}
	user, err := s.Users.FindByID(ctx, input.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "invalid profile principal", nil)
	}
	if err == nil && user.State == model.UserStateDeleted {
		return nil, newError(ErrUserDeleted, "user is deleted", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find profile user", err)
	}
	return &ProfileResult{Profile: profileDTO(user)}, nil
}

func (s Service) SendRegisterCode(ctx context.Context, input SendRegisterCodeInput) (*SendRegisterCodeResult, error) {
	email := normalizeIdentifier(input.Email)
	if email == "" {
		return nil, newError(ErrInvalidInput, "email is required", nil)
	}
	if !isAllowedEmailDomain(email) {
		return nil, &Error{Kind: KindInvalidInput, Code: errcode.CodeEmailDomainNotAllowed, Message: "邮箱域名不允许"}
	}
	if err := s.checkEmailLimit(ctx, email, input.ClientIP); err != nil {
		return nil, err
	}
	code, err := generateVerificationCode()
	if err != nil {
		return nil, newError(ErrInternal, "generate verification code", err)
	}
	if err := s.VerificationCode.SaveVerificationCode(ctx, string(mailer.VerificationPurposeRegister), email, code, verificationTTL); err != nil {
		return nil, newError(ErrInternal, "save verification code", err)
	}
	if err := s.Mailer.SendVerificationCode(ctx, email, code, mailer.VerificationPurposeRegister); err != nil {
		slog.Error("send register verification email", "email", email, "error", err)
		return nil, newError(ErrEmailFailed, "邮件发送失败，请稍后重试", err)
	}
	if auditErr := s.audit(ctx, nil, "register_send_code", "verification_code", nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"login_email": email}); auditErr != nil {
		slog.Error("audit register send code", "email", email, "error", auditErr)
	}
	return &SendRegisterCodeResult{Email: email, ExpiresIn: int(verificationTTL.Seconds())}, nil
}

func (s Service) VerifyRegisterCode(ctx context.Context, input VerifyRegisterCodeInput) (*VerifyRegisterCodeResult, error) {
	email := normalizeIdentifier(input.Email)
	if email == "" || input.Code == "" {
		return nil, newError(ErrInvalidInput, "email and code are required", nil)
	}
	if !isAllowedEmailDomain(email) {
		return nil, &Error{Kind: KindInvalidInput, Code: errcode.CodeEmailDomainNotAllowed, Message: "邮箱域名不允许"}
	}
	stored, found, err := s.VerificationCode.ConsumeVerificationCode(ctx, string(mailer.VerificationPurposeRegister), email)
	if err != nil {
		return nil, newError(ErrInternal, "consume verification code", err)
	}
	if !found {
		return nil, newError(ErrVerificationCodeExpired, "验证码已过期或不存在", nil)
	}
	if stored != input.Code {
		return nil, newError(ErrVerificationCodeWrong, "验证码错误", nil)
	}
	ticket, err := generateRegisterTicket()
	if err != nil {
		return nil, newError(ErrInternal, "generate register ticket", err)
	}
	if err := s.RegisterTicket.SaveRegisterTicket(ctx, ticket, email, verificationTTL); err != nil {
		return nil, newError(ErrInternal, "save register ticket", err)
	}
	if auditErr := s.audit(ctx, nil, "register_verify_code", "verification_code", nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"login_email": email}); auditErr != nil {
		slog.Error("audit register verify code", "email", email, "error", auditErr)
	}
	return &VerifyRegisterCodeResult{RegisterTicket: ticket, Email: email, ExpiresIn: int(verificationTTL.Seconds())}, nil
}

func (s Service) Register(ctx context.Context, input RegisterInput) (*RegisterResult, error) {
	ticket := strings.TrimSpace(input.RegisterTicket)
	if ticket == "" {
		return nil, newError(ErrRegisterTicketInvalid, "Register-Ticket is required", nil)
	}
	// The contract accepts registration_state + oauth_state for the third-party
	// OAuth no-binding branch; reject them until OAuth login issues such states,
	// so nothing silently pretends to bind an identity. Validate before the
	// ticket so a rejected request does not burn the one-time ticket.
	if strings.TrimSpace(input.RegistrationState) != "" || strings.TrimSpace(input.OAuthState) != "" {
		return nil, newError(ErrInvalidInput, "registration_state 无效：第三方 OAuth 注册尚未开放", nil)
	}

	name := strings.TrimSpace(input.Name)
	studentID := strings.TrimSpace(input.StudentID)
	phone := strings.TrimSpace(input.PhoneNumber)
	qq := strings.TrimSpace(input.QQNumber)
	college := model.College(strings.TrimSpace(input.College))
	major := strings.TrimSpace(input.Major)
	password := input.Password
	if name == "" || studentID == "" || phone == "" || qq == "" || college == "" || major == "" || password == "" {
		return nil, newError(ErrInvalidInput, "注册信息不完整", nil)
	}
	if !college.Valid() {
		return nil, newError(ErrInvalidInput, "学院不在枚举范围内", nil)
	}
	if len(password) < 8 {
		return nil, newError(ErrPasswordTooShort, "密码长度不足 8 位", nil)
	}

	email, found, err := s.RegisterTicket.ConsumeRegisterTicket(ctx, ticket)
	if err != nil {
		return nil, newError(ErrInternal, "consume register ticket", err)
	}
	if !found {
		return nil, newError(ErrRegisterTicketInvalid, "Register-Ticket 无效或已过期", nil)
	}
	if !isAllowedEmailDomain(email) {
		return nil, &Error{Kind: KindInvalidInput, Code: errcode.CodeEmailDomainNotAllowed, Message: "邮箱域名不允许"}
	}

	exists, err := s.Users.ExistsByLoginEmail(ctx, email)
	if err != nil {
		return nil, newError(ErrInternal, "check email existence", err)
	}
	if exists {
		return nil, newError(ErrEmailAlreadyRegistered, "邮箱已被注册", nil)
	}
	exists, err = s.Users.ExistsByStudentID(ctx, studentID)
	if err != nil {
		return nil, newError(ErrInternal, "check student id existence", err)
	}
	if exists {
		return nil, newError(ErrStudentIDOccupied, "学号已被占用", nil)
	}

	passwordHash, err := s.Passwords.HashPassword(password)
	if err != nil {
		return nil, newError(ErrInternal, "hash password", err)
	}

	user := &model.User{
		Role:         model.UserRoleFreshman,
		State:        model.UserStateNJUPTer,
		College:      college,
		Name:         name,
		PhoneNumber:  phone,
		QQNumber:     qq,
		PasswordHash: passwordHash,
		StudentID:    studentID,
		LoginEmail:   email,
		Major:        major,
	}
	profile := &model.Profile{}

	if createErr := s.Users.CreateWithProfile(ctx, user, profile); createErr != nil {
		if isDuplicateError(createErr) {
			return nil, newError(ErrEmailAlreadyRegistered, "邮箱已被注册", createErr)
		}
		return nil, newError(ErrInternal, "create user", createErr)
	}

	client, err := s.findInternalClient(ctx)
	if err != nil {
		return nil, err
	}
	pair, err := s.issuePair(user, client, 0, "", sessionScopes)
	if err != nil {
		return nil, err
	}
	if err := s.Tokens.CreatePair(ctx, pair.access, pair.refresh); err != nil {
		return nil, newError(ErrInternal, "create token pair", err)
	}

	if auditErr := s.audit(ctx, &user.ID, "register", "session", nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"login_email": email}); auditErr != nil {
		slog.Error("audit register", "user_id", user.ID, "error", auditErr)
	}
	return &RegisterResult{
		AccessToken:      pair.accessToken,
		RefreshToken:     pair.refreshToken,
		TokenType:        BearerTokenType,
		Scope:            pair.scopeClaim,
		AccessExpiresAt:  pair.access.ExpiresAt,
		RefreshExpiresAt: pair.refresh.ExpiresAt,
		Profile:          profileDTO(user),
	}, nil
}

func (s Service) ForgotPasswordSendCode(ctx context.Context, input ForgotPasswordInput) (*ForgotPasswordResult, error) {
	email := normalizeIdentifier(input.Email)
	if email == "" {
		return nil, newError(ErrInvalidInput, "email is required", nil)
	}
	if err := s.checkEmailLimit(ctx, email, input.ClientIP); err != nil {
		return nil, err
	}
	user, err := s.Users.FindByLoginEmail(ctx, email)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrUnknownIdentifier, "登录邮箱不存在", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find login email", err)
	}
	code, err := generateVerificationCode()
	if err != nil {
		return nil, newError(ErrInternal, "generate verification code", err)
	}
	if saveErr := s.VerificationCode.SaveVerificationCode(ctx, string(mailer.VerificationPurposeResetPassword), email, code, verificationTTL); saveErr != nil {
		return nil, newError(ErrInternal, "save verification code", saveErr)
	}
	if err := s.Mailer.SendVerificationCode(ctx, email, code, mailer.VerificationPurposeResetPassword); err != nil {
		slog.Error("send forgot password email", "email", email, "error", err)
		return nil, newError(ErrEmailFailed, "邮件发送失败，请稍后重试", err)
	}
	if auditErr := s.audit(ctx, &user.ID, "forgot_password_send_code", "verification_code", nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"login_email": email}); auditErr != nil {
		slog.Error("audit forgot password send code", "email", email, "error", auditErr)
	}
	return &ForgotPasswordResult{Email: email, ExpiresIn: int(verificationTTL.Seconds())}, nil
}

func (s Service) ResetPassword(ctx context.Context, input ResetPasswordInput) (*ResetPasswordResult, error) {
	email := normalizeIdentifier(input.Email)
	if email == "" || input.Code == "" || input.Password == "" {
		return nil, newError(ErrInvalidInput, "email, code and password are required", nil)
	}
	// Validate everything possible before consuming the one-time code, so a
	// rejected request does not force the user to request a fresh code.
	if len(input.Password) < 8 {
		return nil, newError(ErrPasswordTooShort, "密码长度不足 8 位", nil)
	}
	stored, found, err := s.VerificationCode.ConsumeVerificationCode(ctx, string(mailer.VerificationPurposeResetPassword), email)
	if err != nil {
		return nil, newError(ErrInternal, "consume verification code", err)
	}
	if !found {
		return nil, newError(ErrVerificationCodeExpired, "验证码已过期或不存在", nil)
	}
	if stored != input.Code {
		return nil, newError(ErrVerificationCodeWrong, "验证码错误", nil)
	}
	user, err := s.Users.FindByLoginEmail(ctx, email)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrUnknownIdentifier, "登录邮箱不存在", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find login email", err)
	}
	if s.Passwords.VerifyPassword(input.Password, user.PasswordHash) == nil {
		return nil, newError(ErrPasswordUnchanged, "新密码不能与旧密码相同", nil)
	}
	passwordHash, err := s.Passwords.HashPassword(input.Password)
	if err != nil {
		return nil, newError(ErrInternal, "hash password", err)
	}
	if err := s.Users.UpdatePasswordAndBumpTokenVersion(ctx, user.ID, passwordHash); err != nil {
		return nil, newError(ErrInternal, "update password", err)
	}
	now := s.now()
	entries, revokeErr := s.Tokens.RevokeAllByUser(ctx, user.ID, now)
	if revokeErr != nil {
		slog.Error("revoke tokens after password reset", "user_id", user.ID, "error", revokeErr)
	}
	s.deliverBlacklist(ctx, entries, now)
	if s.Failures != nil {
		if resetErr := s.Failures.Reset(ctx, "identifier:"+email); resetErr != nil {
			slog.Error("reset login failures after password reset", "email", email, "error", resetErr)
		}
	}
	if auditErr := s.audit(ctx, &user.ID, "reset_password", "session", nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"login_email": email}); auditErr != nil {
		slog.Error("audit reset password", "user_id", user.ID, "error", auditErr)
	}
	return &ResetPasswordResult{Email: email}, nil
}

func (s Service) ChangePassword(ctx context.Context, input ChangePasswordInput) (*ChangePasswordResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "invalid principal", nil)
	}
	if input.OldPassword == "" || input.NewPassword == "" {
		return nil, newError(ErrInvalidInput, "old_password and new_password are required", nil)
	}
	if len(input.NewPassword) < 8 {
		return nil, newError(ErrPasswordTooShort, "密码长度不足 8 位", nil)
	}
	if input.NewPassword == input.OldPassword {
		return nil, newError(ErrPasswordUnchanged, "新密码不能与旧密码相同", nil)
	}
	user, err := s.Users.FindByID(ctx, input.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "invalid principal", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find change password user", err)
	}
	if user.State == model.UserStateDeleted {
		return nil, newError(ErrUserDeleted, "user is deleted", nil)
	}
	if verifyErr := s.Passwords.VerifyPassword(input.OldPassword, user.PasswordHash); verifyErr != nil {
		if auditErr := s.audit(ctx, &user.ID, "change_password", "session", nil, false, errcode.CodePasswordInvalid, input.ClientIP, input.UserAgent, nil); auditErr != nil {
			slog.Error("audit change password failure", "user_id", user.ID, "error", auditErr)
		}
		return nil, newError(ErrPasswordInvalid, "旧密码错误", verifyErr)
	}
	passwordHash, err := s.Passwords.HashPassword(input.NewPassword)
	if err != nil {
		return nil, newError(ErrInternal, "hash password", err)
	}
	if err := s.Users.UpdatePasswordAndBumpTokenVersion(ctx, user.ID, passwordHash); err != nil {
		return nil, newError(ErrInternal, "update password", err)
	}
	now := s.now()
	entries, revokeErr := s.Tokens.RevokeAllByUser(ctx, user.ID, now)
	if revokeErr != nil {
		slog.Error("revoke tokens after password change", "user_id", user.ID, "error", revokeErr)
	}
	s.deliverBlacklist(ctx, entries, now)
	if auditErr := s.audit(ctx, &user.ID, "change_password", "session", nil, true, 0, input.ClientIP, input.UserAgent, nil); auditErr != nil {
		slog.Error("audit change password", "user_id", user.ID, "error", auditErr)
	}
	return &ChangePasswordResult{UserID: user.ID}, nil
}

func (s Service) BindEmailSendCode(ctx context.Context, input BindEmailSendCodeInput) (*BindEmailSendCodeResult, error) {
	email := normalizeIdentifier(input.Email)
	if email == "" {
		return nil, newError(ErrInvalidInput, "email is required", nil)
	}
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "invalid principal", nil)
	}
	if err := s.checkEmailLimit(ctx, email, input.ClientIP); err != nil {
		return nil, err
	}
	if existing, findErr := s.Identities.FindByProviderID(ctx, model.LoginMethodOtherMail, email); findErr == nil {
		if existing.UserID == input.UserID {
			return nil, newError(ErrIdentityAlreadyBound, "该邮箱已绑定", nil)
		}
		return nil, newError(ErrIdentityOccupied, "该邮箱已被其他账号绑定", nil)
	} else if !errors.Is(findErr, repository.ErrNotFound) {
		return nil, newError(ErrInternal, "find identity", findErr)
	}
	count, err := s.Identities.CountByUserAndProvider(ctx, input.UserID, model.LoginMethodOtherMail)
	if err != nil {
		return nil, newError(ErrInternal, "count identities", err)
	}
	if count >= maxOtherMailBindings {
		return nil, newError(ErrIdentityLimitReached, "第三方邮箱绑定数量已达上限", nil)
	}
	code, err := generateVerificationCode()
	if err != nil {
		return nil, newError(ErrInternal, "generate verification code", err)
	}
	if saveErr := s.VerificationCode.SaveVerificationCode(ctx, string(mailer.VerificationPurposeBindEmail), email, code, verificationTTL); saveErr != nil {
		return nil, newError(ErrInternal, "save verification code", saveErr)
	}
	ticket, err := generateBindTicket()
	if err != nil {
		return nil, newError(ErrInternal, "generate bind ticket", err)
	}
	if err := s.BindTicket.SaveBindTicket(ctx, ticket, BindTicketPayload{Email: email, UserID: input.UserID}, verificationTTL); err != nil {
		return nil, newError(ErrInternal, "save bind ticket", err)
	}
	if err := s.Mailer.SendVerificationCode(ctx, email, code, mailer.VerificationPurposeBindEmail); err != nil {
		slog.Error("send bind email verification", "email", email, "error", err)
		return nil, newError(ErrEmailFailed, "邮件发送失败，请稍后重试", err)
	}
	if auditErr := s.audit(ctx, &input.UserID, "bind_email_send_code", "verification_code", nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"email": email}); auditErr != nil {
		slog.Error("audit bind email send code", "email", email, "error", auditErr)
	}
	return &BindEmailSendCodeResult{BindTicket: ticket, ExpiresIn: int(verificationTTL.Seconds())}, nil
}

func (s Service) BindEmailVerify(ctx context.Context, input BindEmailVerifyInput) (*BindEmailVerifyResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "invalid principal", nil)
	}
	ticket := strings.TrimSpace(input.BindTicket)
	if ticket == "" || input.Code == "" {
		return nil, newError(ErrInvalidInput, "bind_ticket and code are required", nil)
	}
	payload, found, err := s.BindTicket.ConsumeBindTicket(ctx, ticket)
	if err != nil {
		return nil, newError(ErrInternal, "consume bind ticket", err)
	}
	if !found {
		return nil, newError(ErrBindTicketInvalid, "Bind-Ticket 无效或已过期", nil)
	}
	if payload.UserID != input.UserID {
		return nil, newError(ErrBindTicketInvalid, "Bind-Ticket 不属于当前用户", nil)
	}
	stored, codeFound, err := s.VerificationCode.ConsumeVerificationCode(ctx, string(mailer.VerificationPurposeBindEmail), payload.Email)
	if err != nil {
		return nil, newError(ErrInternal, "consume verification code", err)
	}
	if !codeFound {
		return nil, newError(ErrVerificationCodeExpired, "验证码已过期或不存在", nil)
	}
	if stored != input.Code {
		return nil, newError(ErrVerificationCodeWrong, "验证码错误", nil)
	}
	if existing, findErr := s.Identities.FindByProviderID(ctx, model.LoginMethodOtherMail, payload.Email); findErr == nil {
		if existing.UserID == input.UserID {
			return nil, newError(ErrIdentityAlreadyBound, "该邮箱已绑定", nil)
		}
		return nil, newError(ErrIdentityOccupied, "该邮箱已被其他账号绑定", nil)
	} else if !errors.Is(findErr, repository.ErrNotFound) {
		return nil, newError(ErrInternal, "find identity", findErr)
	}
	identity := &model.Identity{
		UserID:     input.UserID,
		Provider:   model.LoginMethodOtherMail,
		ProviderID: payload.Email,
	}
	if err := s.Identities.CreateWithinLimit(ctx, identity, maxOtherMailBindings); err != nil {
		if errors.Is(err, repository.ErrLimitExceeded) {
			return nil, newError(ErrIdentityLimitReached, "第三方邮箱绑定数量已达上限", nil)
		}
		if isDuplicateError(err) {
			return nil, newError(ErrIdentityOccupied, "该邮箱已被其他账号绑定", err)
		}
		return nil, newError(ErrInternal, "create identity", err)
	}
	if auditErr := s.audit(ctx, &input.UserID, "oauth_bind", "identity", nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"provider": string(model.LoginMethodOtherMail), "provider_id": payload.Email}); auditErr != nil {
		slog.Error("audit bind email", "user_id", input.UserID, "error", auditErr)
	}
	return &BindEmailVerifyResult{
		Email: payload.Email,
		Identity: IdentityDTO{
			ID:             identity.ID,
			Provider:       string(identity.Provider),
			ProviderID:     identity.ProviderID,
			IdentityData:   identity.IdentityData,
			TokenExpiresAt: identity.TokenExpiresAt,
			CreatedAt:      identity.CreatedAt,
			UpdatedAt:      identity.UpdatedAt,
		},
	}, nil
}

func (s Service) checkEndpointLimit(ctx context.Context, endpoint, subject string) error {
	if s.Limiter == nil {
		return nil
	}
	result, err := s.Limiter.Allow(ctx, endpoint, subject)
	if err != nil {
		return newError(ErrInternal, "check endpoint limit", err)
	}
	if !result.Allowed {
		return withRetryAfter(newError(ErrRateLimited, "rate limited", nil), result.RetryAfter)
	}
	return nil
}

// checkEmailLimit throttles verification-code sending on two independent
// dimensions: the target email (stops repeated mail to one inbox) and the
// caller IP (stops one attacker fanning out across many addresses to drain
// SMTP quota).
func (s Service) checkEmailLimit(ctx context.Context, email, clientIP string) error {
	if s.EmailLimiter != nil {
		result, err := s.EmailLimiter.Allow(ctx, "send_email", "email:"+email)
		if err != nil {
			return newError(ErrInternal, "check email limit", err)
		}
		if !result.Allowed {
			return withRetryAfter(newError(ErrRateLimited, "rate limited", nil), result.RetryAfter)
		}
	}
	if s.EmailIPLimiter != nil && strings.TrimSpace(clientIP) != "" {
		result, err := s.EmailIPLimiter.Allow(ctx, "send_email", "ip:"+strings.TrimSpace(clientIP))
		if err != nil {
			return newError(ErrInternal, "check email ip limit", err)
		}
		if !result.Allowed {
			return withRetryAfter(newError(ErrRateLimited, "rate limited", nil), result.RetryAfter)
		}
	}
	return nil
}

func (s Service) deliverBlacklist(ctx context.Context, entries []model.BlacklistEntry, now time.Time) {
	if s.Blacklist == nil {
		return
	}
	for _, entry := range entries {
		ttl := entry.ExpiresAt.Sub(now)
		if ttl <= 0 || strings.TrimSpace(entry.TokenID) == "" {
			continue
		}
		if err := s.Blacklist.BlacklistJTI(ctx, entry.TokenID, ttl); err != nil {
			slog.Error("deliver token blacklist entry", "token_id", entry.TokenID, "error", err)
		}
	}
}

func (s Service) checkLoginLock(ctx context.Context, key string) error {
	if s.Failures == nil {
		return nil
	}
	locked, retryAfter, err := s.Failures.IsLocked(ctx, key)
	if err != nil {
		return newError(ErrInternal, "check login lockout", err)
	}
	if locked {
		return withRetryAfter(newError(ErrLocked, "login locked", nil), retryAfter)
	}
	return nil
}

func (s Service) failLogin(ctx context.Context, user *model.User, input LoginInput, failureKey string, sentinel *Error, message string, cause error) error {
	locked := false
	lockTTL := time.Duration(0)
	if s.Failures != nil {
		result, err := s.Failures.RecordFailure(ctx, failureKey)
		if err != nil {
			return newError(ErrInternal, "record login failure", err)
		}
		locked = result.Locked
		lockTTL = result.TTL
	}
	if err := s.audit(ctx, loginUserID(user), "login", "session", nil, false, sentinel.Code, input.ClientIP, input.UserAgent, map[string]any{"method": loginMethod(user, input.Identifier)}); err != nil {
		slog.Error("audit login failure", "error", err)
	}
	if locked {
		return withRetryAfter(newError(ErrLocked, "login locked", nil), lockTTL)
	}
	return newError(sentinel, message, cause)
}

func (s Service) findInternalClient(ctx context.Context) (*model.OAuthClient, error) {
	if strings.TrimSpace(s.InternalClientID) == "" || s.Clients == nil {
		return nil, newError(ErrInternal, "internal client is not configured", nil)
	}
	client, err := s.Clients.FindActiveByClientID(ctx, strings.TrimSpace(s.InternalClientID))
	if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInvalidArgument) {
		return nil, newError(ErrInternal, "internal client is not available", err)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find internal client", err)
	}
	if client.ClientType != model.ClientTypeFirstParty || client.ClientSecretHash != nil {
		return nil, newError(ErrInternal, "internal client is not a public first-party client", nil)
	}
	if ok, err := scope.Equal([]string(client.Scopes), sessionScopes); err != nil || !ok {
		return nil, newError(ErrInternal, "internal client scopes must be canonical session scopes", err)
	}
	return client, nil
}
