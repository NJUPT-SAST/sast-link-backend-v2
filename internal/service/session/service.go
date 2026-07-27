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
	if passwordErr := s.Passwords.VerifyPassword(ctx, input.Password, user.PasswordHash); passwordErr != nil {
		// A cancelled or timed-out caller never proved anything about the password,
		// so it must not be recorded as a failed attempt: doing so would let a
		// client that disconnects mid-login drive its own account into the lockout
		// window.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, newError(ErrDependencyUnavailable, "password verification abandoned", passwordErr)
		}
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
			// A stale counter can lock this identifier until its 15min window
			// expires, which is strictly better than revoking a valid session
			// and refusing every login for as long as Redis is unavailable.
			slog.WarnContext(ctx, "reset login failures unavailable", "error", resetErr)
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
		s.auditRefresh(ctx, current.UserID, &current.FamilyID, false, input)
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
			s.auditRefresh(ctx, current.UserID, &current.FamilyID, false, input)
			return nil, newError(ErrInvalidToken, "invalid refresh token", rotateErr)
		}
		return nil, newError(ErrInternal, "rotate refresh token", rotateErr)
	}
	s.auditRefresh(ctx, current.UserID, &current.FamilyID, true, input)
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
	if !validEmailFormat(email) {
		return nil, newError(ErrInvalidInput, "邮箱格式不正确", nil)
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
		return nil, newError(ErrDependencyUnavailable, "save verification code", err)
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
	if !validEmailFormat(email) {
		return nil, newError(ErrInvalidInput, "邮箱格式不正确", nil)
	}
	if !isAllowedEmailDomain(email) {
		return nil, &Error{Kind: KindInvalidInput, Code: errcode.CodeEmailDomainNotAllowed, Message: "邮箱域名不允许"}
	}
	purpose := string(mailer.VerificationPurposeRegister)
	if err := s.verifyCode(ctx, purpose, email, input.Code); err != nil {
		return nil, err
	}
	ticket, err := generateRegisterTicket()
	if err != nil {
		return nil, newError(ErrInternal, "generate register ticket", err)
	}
	if err := s.RegisterTicket.SaveRegisterTicket(ctx, ticket, email, verificationTTL); err != nil {
		// The code already matched and was consumed; without a ticket the user has
		// to restart, so make sure the spent code cannot be reused either.
		s.discardCode(ctx, purpose, email)
		return nil, newError(ErrDependencyUnavailable, "save register ticket", err)
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

	// Read the ticket first and only spend it once every rejectable condition has
	// been checked: a recoverable error such as an occupied student ID must not
	// cost the user their one-time ticket and force a new send-code round trip.
	email, found, err := s.RegisterTicket.PeekRegisterTicket(ctx, ticket)
	if err != nil {
		return nil, newError(ErrDependencyUnavailable, "read register ticket", err)
	}
	if !found {
		return nil, newError(ErrRegisterTicketInvalid, "Register-Ticket 无效或已过期", nil)
	}
	if !isAllowedEmailDomain(email) {
		return nil, &Error{Kind: KindInvalidInput, Code: errcode.CodeEmailDomainNotAllowed, Message: "邮箱域名不允许"}
	}

	exists, err := s.Users.ExistsAsEmailAnywhere(ctx, email)
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

	passwordHash, err := s.Passwords.HashPassword(ctx, password)
	if err != nil {
		return nil, s.hashError(ctx, err)
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

	// The ticket is still live at this point. login_email carries a UNIQUE
	// constraint, so the INSERT itself is the serialization point for concurrent
	// registrations of the same email — the ticket does not need to elect a winner,
	// and keeping it until the account exists means a losing racer can retry.
	if createErr := s.Users.CreateWithProfile(ctx, user, profile); createErr != nil {
		// A unique violation here means the pre-flight checks raced a concurrent
		// registration. The table has two unique constraints, so dispatch on the
		// constraint name: reporting "邮箱已被注册" for a student-ID clash points the
		// user at the wrong field.
		switch constraint := duplicateConstraint(createErr); constraint {
		case userStudentIDConstraint:
			return nil, newError(ErrStudentIDOccupied, "学号已被占用", createErr)
		case userLoginEmailConstraint:
			return nil, newError(ErrEmailAlreadyRegistered, "邮箱已被注册", createErr)
		case "":
		default:
			// An unmapped unique constraint. Report a generic conflict rather than
			// guessing a field, and log the name so the mapping can be added.
			slog.ErrorContext(ctx, "unmapped unique violation on register", "constraint", constraint)
			return nil, newError(ErrConflict, "注册信息与现有账号冲突", createErr)
		}
		return nil, newError(ErrInternal, "create user", createErr)
	}

	// The account exists, so the ticket has served its purpose. A failure here
	// leaves a live ticket whose email is already registered; the next attempt is
	// rejected by the email-exists check, so it cannot create a second account.
	if consumeErr := s.RegisterTicket.ConsumeRegisterTicket(ctx, ticket); consumeErr != nil {
		slog.WarnContext(ctx, "consume register ticket after account creation", "user_id", user.ID, "error", consumeErr)
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
	if !validEmailFormat(email) {
		return nil, newError(ErrInvalidInput, "邮箱格式不正确", nil)
	}
	if err := s.checkEmailLimit(ctx, email, input.ClientIP); err != nil {
		return nil, err
	}
	// Always report success regardless of account existence: revealing that an
	// address is or is not registered lets unauthenticated callers enumerate
	// valid accounts for targeted phishing or credential stuffing. The email is
	// only actually generated and sent when the account exists.
	user, err := s.Users.FindByLoginEmail(ctx, email)
	if errors.Is(err, repository.ErrNotFound) {
		if auditErr := s.audit(ctx, nil, "forgot_password_send_code", "verification_code", nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"login_email": email}); auditErr != nil {
			slog.Error("audit forgot password send code", "email", email, "error", auditErr)
		}
		return &ForgotPasswordResult{Email: email, ExpiresIn: int(verificationTTL.Seconds())}, nil
	}
	if err != nil {
		return nil, newError(ErrInternal, "find login email", err)
	}
	code, err := generateVerificationCode()
	if err != nil {
		return nil, newError(ErrInternal, "generate verification code", err)
	}
	if saveErr := s.VerificationCode.SaveVerificationCode(ctx, string(mailer.VerificationPurposeResetPassword), email, code, verificationTTL); saveErr != nil {
		return nil, newError(ErrDependencyUnavailable, "save verification code", saveErr)
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
	if !validEmailFormat(email) {
		return nil, newError(ErrInvalidInput, "邮箱格式不正确", nil)
	}
	// Validate everything possible before consuming the one-time code, so a
	// rejected request does not force the user to request a fresh code.
	if len(input.Password) < 8 {
		return nil, newError(ErrPasswordTooShort, "密码长度不足 8 位", nil)
	}
	if err := s.verifyCode(ctx, string(mailer.VerificationPurposeResetPassword), email, input.Code); err != nil {
		return nil, err
	}
	user, err := s.Users.FindByLoginEmail(ctx, email)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrUnknownIdentifier, "登录邮箱不存在", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "find login email", err)
	}
	// Distinguish "differs from the old password" from "could not check": a
	// cancelled verification returns non-nil too, which would otherwise be read as
	// a successful difference check.
	switch sameErr := s.Passwords.VerifyPassword(ctx, input.Password, user.PasswordHash); {
	case sameErr == nil:
		return nil, newError(ErrPasswordUnchanged, "新密码不能与旧密码相同", nil)
	case ctx.Err() != nil:
		return nil, newError(ErrDependencyUnavailable, "password comparison abandoned", sameErr)
	}
	passwordHash, err := s.Passwords.HashPassword(ctx, input.Password)
	if err != nil {
		return nil, s.hashError(ctx, err)
	}
	now := s.now()
	// The password rewrite and the session revocation share one transaction:
	// reporting success while live refresh tokens survive would contradict the
	// "请重新登录" contract, so a revocation failure must fail the whole call.
	entries, err := s.Users.UpdatePasswordAndRevokeSessions(ctx, user.ID, passwordHash, now)
	if err != nil {
		return nil, newError(ErrInternal, "reset password and revoke sessions", err)
	}
	s.deliverBlacklist(ctx, entries, now)
	s.clearLoginFailures(ctx, user, email)
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
	if verifyErr := s.Passwords.VerifyPassword(ctx, input.OldPassword, user.PasswordHash); verifyErr != nil {
		// An abandoned verification is not a wrong password: auditing it as one
		// would fill the log with phantom failures for clients that disconnected.
		if ctx.Err() != nil {
			return nil, newError(ErrDependencyUnavailable, "password verification abandoned", verifyErr)
		}
		if auditErr := s.audit(ctx, &user.ID, "change_password", "session", nil, false, errcode.CodePasswordInvalid, input.ClientIP, input.UserAgent, nil); auditErr != nil {
			slog.Error("audit change password failure", "user_id", user.ID, "error", auditErr)
		}
		return nil, newError(ErrPasswordInvalid, "旧密码错误", verifyErr)
	}
	passwordHash, err := s.Passwords.HashPassword(ctx, input.NewPassword)
	if err != nil {
		return nil, s.hashError(ctx, err)
	}
	now := s.now()
	entries, err := s.Users.UpdatePasswordAndRevokeSessions(ctx, user.ID, passwordHash, now)
	if err != nil {
		return nil, newError(ErrInternal, "change password and revoke sessions", err)
	}
	s.deliverBlacklist(ctx, entries, now)
	s.clearLoginFailures(ctx, user, user.LoginEmail)
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
	if !validEmailFormat(email) {
		return nil, newError(ErrInvalidInput, "邮箱格式不正确", nil)
	}
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "invalid principal", nil)
	}
	if err := s.checkEmailLimit(ctx, email, input.ClientIP); err != nil {
		return nil, err
	}
	if _, findErr := s.Identities.FindByProviderID(ctx, model.LoginMethodOtherMail, email); findErr == nil {
		// The conflict response must not reveal who owns the address: a distinct
		// "already bound to you" error lets any authenticated caller enumerate
		// other users' bindings. Every occupied email gets the same reply; the
		// caller refreshes their own binding list through GET /user/profile.
		return nil, newError(ErrIdentityOccupied, "该邮箱已被绑定或占用", nil)
	} else if !errors.Is(findErr, repository.ErrNotFound) {
		return nil, newError(ErrInternal, "find identity", findErr)
	}
	if emailExists, err := s.Users.ExistsAsEmailAnywhere(ctx, email); err != nil {
		return nil, newError(ErrInternal, "check email existence", err)
	} else if emailExists {
		return nil, newError(ErrIdentityOccupied, "该邮箱已被绑定或占用", nil)
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
		return nil, newError(ErrDependencyUnavailable, "save verification code", saveErr)
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
	// Read the ticket without consuming it: a wrong verification code must not
	// cost the user their Bind-Ticket, or every typo forces a fresh send-code
	// round trip. The ticket is consumed only once the binding is about to happen.
	payload, found, err := s.BindTicket.PeekBindTicket(ctx, ticket)
	if err != nil {
		return nil, newError(ErrDependencyUnavailable, "read bind ticket", err)
	}
	if !found {
		return nil, newError(ErrBindTicketInvalid, "Bind-Ticket 无效或已过期", nil)
	}
	if payload.UserID != input.UserID {
		return nil, newError(ErrBindTicketInvalid, "Bind-Ticket 不属于当前用户", nil)
	}
	purpose := string(mailer.VerificationPurposeBindEmail)
	if verifyErr := s.verifyCode(ctx, purpose, payload.Email, input.Code); verifyErr != nil {
		return nil, verifyErr
	}
	// The code matched, so the ticket has served its purpose. Consuming it here
	// also serializes concurrent requests replaying the same ticket: only the
	// caller that removes the key proceeds to insert the identity.
	consumed, err := s.BindTicket.ConsumeBindTicket(ctx, ticket)
	if err != nil {
		s.discardCode(ctx, purpose, payload.Email)
		return nil, newError(ErrDependencyUnavailable, "consume bind ticket", err)
	}
	if !consumed {
		s.discardCode(ctx, purpose, payload.Email)
		return nil, newError(ErrBindTicketInvalid, "Bind-Ticket 无效或已过期", nil)
	}
	if _, findErr := s.Identities.FindByProviderID(ctx, model.LoginMethodOtherMail, payload.Email); findErr == nil {
		return nil, newError(ErrIdentityOccupied, "该邮箱已被绑定或占用", nil)
	} else if !errors.Is(findErr, repository.ErrNotFound) {
		return nil, newError(ErrInternal, "find identity", findErr)
	}
	if emailExists, err := s.Users.ExistsAsEmailAnywhere(ctx, payload.Email); err != nil {
		return nil, newError(ErrInternal, "check email existence", err)
	} else if emailExists {
		return nil, newError(ErrIdentityOccupied, "该邮箱已被绑定或占用", nil)
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
		// Redis-backed throttling has no durable fallback. Rejecting every
		// request would take the endpoint down entirely, so allow the call and
		// rely on PBKDF2 cost plus alerting during the outage.
		slog.WarnContext(ctx, "endpoint limiter unavailable, allowing request", "endpoint", endpoint, "error", err)
		return nil
	}
	if !result.Allowed {
		return withRetryAfter(newError(ErrRateLimited, "rate limited", nil), result.RetryAfter)
	}
	return nil
}

// checkEmailLimit throttles verification-code sending on two independent
// dimensions: the target email (stops repeated mail to one inbox) and the
// caller IP (stops one attacker fanning out across many addresses to drain
// SMTP quota). Limiter outages fail open per the Redis degradation policy
// (PRD §6.0): the flow still fails closed at the Redis code store when Redis
// is fully down, so degradation only matters for transient limiter errors.
func (s Service) checkEmailLimit(ctx context.Context, email, clientIP string) error {
	if s.EmailLimiter != nil {
		result, err := s.EmailLimiter.Allow(ctx, "send_email", "email:"+email)
		switch {
		case err != nil:
			slog.WarnContext(ctx, "email limiter unavailable, allowing request", "error", err)
		case !result.Allowed:
			return withRetryAfter(newError(ErrRateLimited, "rate limited", nil), result.RetryAfter)
		}
	}
	if s.EmailIPLimiter != nil && strings.TrimSpace(clientIP) != "" {
		result, err := s.EmailIPLimiter.Allow(ctx, "send_email", "ip:"+strings.TrimSpace(clientIP))
		switch {
		case err != nil:
			slog.WarnContext(ctx, "email ip limiter unavailable, allowing request", "error", err)
		case !result.Allowed:
			return withRetryAfter(newError(ErrRateLimited, "rate limited", nil), result.RetryAfter)
		}
	}
	return nil
}

func (s Service) deliverBlacklist(ctx context.Context, entries []model.BlacklistEntry, now time.Time) {
	if s.Blacklist == nil {
		return
	}
	batch := make(map[string]time.Duration, len(entries))
	for _, entry := range entries {
		ttl := entry.ExpiresAt.Sub(now)
		if ttl <= 0 || strings.TrimSpace(entry.TokenID) == "" {
			continue
		}
		batch[entry.TokenID] = ttl
	}
	if len(batch) == 0 {
		return
	}
	if err := s.Blacklist.BlacklistJTIBatch(ctx, batch); err != nil {
		// The same-transaction outbox row guarantees a worker retry, so a
		// failed synchronous delivery is expected degradation, not an error.
		slog.WarnContext(ctx, "deliver token blacklist batch, outbox worker will retry", "count", len(batch), "error", err)
	}
}

// verifyCode checks a submitted email code. The store keeps the code alive
// through a bounded number of wrong guesses, so a mistyped digit no longer burns
// it — a wrong guess used to delete the valid code, which let anyone who knew an
// address invalidate its code at will. Once the budget is spent the store drops
// the code and the caller sees the expired outcome.
func (s Service) verifyCode(ctx context.Context, purpose, email, code string) error {
	matched, remaining, err := s.VerificationCode.VerifyVerificationCode(ctx, purpose, email, code)
	if err != nil {
		return newError(ErrDependencyUnavailable, "verify verification code", err)
	}
	if matched {
		return nil
	}
	if remaining <= 0 {
		return newError(ErrVerificationCodeExpired, "验证码已过期或不存在", nil)
	}
	return newError(ErrVerificationCodeWrong, "验证码错误", nil)
}

// hashError classifies a password-derivation failure. Hashing queues behind a
// concurrency gate, so a cancelled caller gets ctx.Err() rather than a genuine
// fault; reporting that as a 500 would blame the server for a client that left.
func (s Service) hashError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return newError(ErrDependencyUnavailable, "password hashing abandoned", err)
	}
	return newError(ErrInternal, "hash password", err)
}

// discardCode drops an already-matched code when a later step of the same flow
// fails, so the spent code cannot be replayed by a retry.
func (s Service) discardCode(ctx context.Context, purpose, email string) {
	if err := s.VerificationCode.DiscardVerificationCode(ctx, purpose, email); err != nil {
		slog.WarnContext(ctx, "discard consumed verification code", "purpose", purpose, "error", err)
	}
}

// clearLoginFailures releases the lockout after a successful password reset or
// change. Login records failures under "user:<id>" once the account is known and
// under "identifier:<email>" before that, so both keys must be cleared or a
// locked-out user stays locked for the rest of the window — defeating the very
// recovery path they just completed. Failures are logged, not returned: the
// password is already changed, and a stale counter expires on its own.
func (s Service) clearLoginFailures(ctx context.Context, user *model.User, email string) {
	if s.Failures == nil || user == nil {
		return
	}
	keys := []string{loginFailureKey(user, email)}
	if identifier := normalizeIdentifier(email); identifier != "" {
		keys = append(keys, "identifier:"+identifier)
	}
	for _, key := range keys {
		if err := s.Failures.Reset(ctx, key); err != nil {
			slog.WarnContext(ctx, "reset login failures after password update", "key", key, "error", err)
		}
	}
}

func (s Service) checkLoginLock(ctx context.Context, key string) error {
	if s.Failures == nil {
		return nil
	}
	locked, retryAfter, err := s.Failures.IsLocked(ctx, key)
	if err != nil {
		slog.WarnContext(ctx, "login lockout state unavailable, allowing attempt", "error", err)
		return nil
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
			// Losing a counter increment must not mask the real rejection
			// reason with a 500; report the original failure instead.
			slog.WarnContext(ctx, "record login failure unavailable", "error", err)
		} else {
			locked = result.Locked
			lockTTL = result.TTL
		}
	}
	if err := s.audit(ctx, loginUserID(user), "login", "session", nil, false, sentinel.Code, input.ClientIP, input.UserAgent, map[string]any{"method": loginMethod(user, input.Identifier)}); err != nil {
		slog.Error("audit login failure", "error", err)
	}
	if locked {
		return withRetryAfter(newError(ErrLocked, "login locked", nil), lockTTL)
	}
	return newError(sentinel, message, cause)
}

// auditRefresh records a refresh rotation outcome. Failures mean the token
// family was revoked as a replay defense, so they carry the invalid-token code;
// the audit itself is fail-open like every other audit call in this service.
func (s Service) auditRefresh(ctx context.Context, userID int64, familyID *string, success bool, input RefreshInput) {
	errCode := 0
	if !success {
		errCode = errcode.CodeAccessTokenInvalid
	}
	if auditErr := s.audit(ctx, &userID, "refresh", "session", familyID, success, errCode, input.ClientIP, input.UserAgent, map[string]any{}); auditErr != nil {
		slog.Error("audit refresh", "family_id", familyID, "error", auditErr)
	}
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
