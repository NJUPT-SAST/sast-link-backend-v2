package session

import (
	"context"
	"errors"
	"log/slog"
	"strconv"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/shared"
)

// ListIdentities returns the caller's own third-party bindings.
func (s Service) ListIdentities(ctx context.Context, input ListIdentitiesInput) (*ListIdentitiesResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	identities, err := s.Identities.ListByUser(ctx, input.UserID)
	if err != nil {
		return nil, newError(ErrInternal, "查询第三方绑定列表失败", err)
	}
	result := make([]IdentityDTO, 0, len(identities))
	for _, identity := range identities {
		result = append(result, identityDTO(identity))
	}
	return &ListIdentitiesResult{Identities: result}, nil
}

// UnbindIdentity removes one of the caller's third-party bindings after
// confirming their current password.
//
// Three guards, in this order:
//
//  1. The identity is resolved scoped to its owner, so a foreign ID reads as
//     missing and cannot be probed.
//  2. The password is verified before anything is deleted, so a stolen access
//     token alone cannot strip login methods off an account.
//  3. The binding must not be the caller's last remaining login method; the
//     check exists for accounts whose only credential is a bound address.
func (s Service) UnbindIdentity(ctx context.Context, input UnbindIdentityInput) (*UnbindIdentityResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	if input.IdentityID <= 0 {
		return nil, newError(ErrIdentityNotFound, "绑定记录不存在", nil)
	}
	if input.Password == "" {
		return nil, newError(ErrInvalidInput, "password 不能为空", nil)
	}
	// Throttle before the password check: repeated wrong-password attempts must
	// consume the budget too, and a cooldown claimed only after the password
	// verifies does nothing against guessing.
	if err := s.checkEndpointLimit(ctx, s.UnbindLimiter, "unbind", "user:"+strconv.FormatInt(input.UserID, 10)); err != nil {
		return nil, err
	}
	// Only the password hash, state, and id are read here.
	user, err := s.Users.FindAuthUserByID(ctx, input.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询待解绑用户失败", err)
	}
	if user.State == model.UserStateDeleted {
		return nil, newError(ErrUserDeleted, "用户已注销", nil)
	}
	identity, err := s.Identities.FindByIDAndUser(ctx, input.IdentityID, input.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrIdentityNotFound, "绑定记录不存在", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询第三方绑定记录失败", err)
	}

	if verifyErr := s.Passwords.VerifyPassword(ctx, input.Password, user.PasswordHash); verifyErr != nil {
		// A caller that went away mid-derivation did not submit a wrong password;
		// auditing it as one would fill the log with phantom failures.
		if ctx.Err() != nil {
			return nil, newError(ErrDependencyUnavailable, "密码校验被中断", verifyErr)
		}
		s.auditUnbind(ctx, input, identity, false, ErrPasswordInvalid.Code)
		return nil, newError(ErrPasswordInvalid, "密码错误", verifyErr)
	}

	// The last-login-method guard runs inside the deleting transaction under a
	// lock on the user row, so two concurrent unbinds cannot both pass a stale
	// snapshot and delete the account's last way to sign in.
	if deleteErr := s.Identities.DeleteIdentityGuardingLoginMethod(ctx, input.IdentityID, input.UserID); deleteErr != nil {
		if errors.Is(deleteErr, repository.ErrNotFound) {
			return nil, newError(ErrIdentityNotFound, "绑定记录不存在", nil)
		}
		if errors.Is(deleteErr, repository.ErrLastLoginMethod) {
			return nil, newError(ErrLastLoginMethod, "不能解绑唯一的登录方式", nil)
		}
		return nil, newError(ErrInternal, "删除第三方绑定记录失败", deleteErr)
	}

	s.auditUnbind(ctx, input, identity, true, 0)
	return &UnbindIdentityResult{
		Provider:   string(identity.Provider),
		ProviderID: identity.ProviderID,
	}, nil
}

func (s Service) auditUnbind(ctx context.Context, input UnbindIdentityInput, identity *model.Identity, success bool, errCode int) {
	detail := map[string]any{
		"provider":    string(identity.Provider),
		"provider_id": identity.ProviderID,
	}
	id := strconv.FormatInt(identity.ID, 10)
	if err := s.audit(ctx, &input.UserID, "oauth_unbind", "identity", &id, shared.NullableString(shared.ActorClientID(input.ActorClientID, s.InternalClientID)), success, errCode,
		input.ClientIP, input.UserAgent, detail); err != nil {
		slog.Error("audit oauth unbind", "user_id", input.UserID, "identity_id", identity.ID, "error", err)
	}
}

// requirePassword steps up a sensitive operation with the current password,
// sharing UnbindIdentity's guard: an access token on its own must not be able
// to bind a new login method (BindEmail*), or a stolen token would turn the
// bind + reset flow into account takeover.
func (s Service) requirePassword(ctx context.Context, userID int64, password string) error {
	if password == "" {
		return newError(ErrInvalidInput, "password 不能为空", nil)
	}
	// Throttle before the password check, like UnbindIdentity: repeated
	// wrong-password attempts must consume the budget, and a cooldown claimed
	// only after success does nothing against guessing. The shared limiter keeps
	// every password step-up on one per-user budget; the endpoint name scopes
	// the Redis key independently of unbind.
	if err := s.checkEndpointLimit(ctx, s.UnbindLimiter, "password_step_up", "user:"+strconv.FormatInt(userID, 10)); err != nil {
		return err
	}
	user, err := s.Users.FindAuthUserByID(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return newError(ErrInvalidToken, "身份主体无效", nil)
	}
	if err != nil {
		return newError(ErrInternal, "查询待操作的用户失败", err)
	}
	if user.State == model.UserStateDeleted {
		return newError(ErrUserDeleted, "用户已注销", nil)
	}
	if verifyErr := s.Passwords.VerifyPassword(ctx, password, user.PasswordHash); verifyErr != nil {
		if ctx.Err() != nil {
			return newError(ErrDependencyUnavailable, "密码校验被中断", verifyErr)
		}
		return newError(ErrPasswordInvalid, "密码错误", verifyErr)
	}
	return nil
}

// auditBindStepUpFailure records a wrong password against the bind flow, the
// same failure signal UnbindIdentity emits on an oauth_unbind. Other step-up
// failures (unknown user, deleted account) are their own errors and carry no
// audit event here.
func (s Service) auditBindStepUpFailure(ctx context.Context, userID int64, actorClientID, clientIP, userAgent string, stepErr error) {
	var serviceErr *Error
	if !errors.As(stepErr, &serviceErr) || serviceErr.Code != errcode.CodePasswordInvalid {
		return
	}
	if auditErr := s.audit(ctx, &userID, "oauth_bind", "session", nil, shared.NullableString(shared.ActorClientID(actorClientID, s.InternalClientID)), false, errcode.CodePasswordInvalid, clientIP, userAgent, nil); auditErr != nil {
		slog.Error("audit bind password failure", "user_id", userID, "error", auditErr)
	}
}
