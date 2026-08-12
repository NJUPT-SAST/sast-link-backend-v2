package session

import (
	"context"
	"errors"
	"log/slog"
	"strconv"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
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
//  2. The password is verified before anything is deleted. A stolen access token
//     alone must not be enough to strip login methods off an account.
//  3. The binding must not be the caller's last remaining login method. The login
//     email is not an identities row, so a user who has one always passes; the
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
	// Throttled before the password check, so repeated wrong-password attempts
	// consume the budget too. The old cooldown was claimed only after the password
	// verified, which meant it did nothing against guessing.
	//
	// Deliberately rate limiting rather than reusing Failures (LoginFailureStore):
	// its keys are shared with password login, so guessing here would lock the
	// victim's login — a token holder could deny them the front door. It also
	// answers with "登录已被锁定", which is wrong on this endpoint. Slowing the
	// endpoint to 3/min already leaves brute force with no practical value; an
	// accumulating lockout would need its own key namespace and error code, at
	// which point it is not a reuse.
	if err := s.checkEndpointLimit(ctx, s.UnbindLimiter, "unbind", "user:"+strconv.FormatInt(input.UserID, 10)); err != nil {
		return nil, err
	}
	// Only the password hash, state, and id are read here; the Profile/Identities
	// preloads of FindByID would be pure waste on this rate-limited path.
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
	// snapshot and delete the account into having no way to sign in.
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
	if err := s.audit(ctx, &input.UserID, "oauth_unbind", "identity", &id, nullableString(s.actorClientID(input.ActorClientID)), success, errCode,
		input.ClientIP, input.UserAgent, detail); err != nil {
		slog.Error("audit oauth unbind", "user_id", input.UserID, "identity_id", identity.ID, "error", err)
	}
}
