package session

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"

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
	user, err := s.Users.FindByID(ctx, input.UserID)
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

	if !hasOtherLoginMethod(user, identity.ID) {
		return nil, newError(ErrLastLoginMethod, "不能解绑唯一的登录方式", nil)
	}

	// Claim the cooldown before deleting. Claiming afterwards would let two
	// concurrent requests both pass the check, which is the rapid repeat the
	// cooldown exists to prevent. Fail-open per PRD §6.0: PostgreSQL owns the
	// binding state, so losing Redis only widens the window.
	cooldownSubject := identity.ProviderID
	if s.UnbindCooldowns != nil {
		acquired, retryAfter, cooldownErr := s.UnbindCooldowns.Acquire(ctx, cooldownSubject)
		switch {
		case cooldownErr != nil:
			slog.WarnContext(ctx, "unbind cooldown unavailable, allowing request", "error", cooldownErr)
		case !acquired:
			return nil, withRetryAfter(newError(ErrRateLimited, "解绑操作过于频繁，请稍后再试", nil), retryAfter)
		}
	}

	if deleteErr := s.Identities.DeleteByIDAndUser(ctx, input.IdentityID, input.UserID); deleteErr != nil {
		// The unbind did not happen, so the cooldown must not hold the address for
		// the rest of the window; the user is entitled to retry immediately.
		s.releaseUnbindCooldown(ctx, cooldownSubject)
		if errors.Is(deleteErr, repository.ErrNotFound) {
			return nil, newError(ErrIdentityNotFound, "绑定记录不存在", nil)
		}
		return nil, newError(ErrInternal, "删除第三方绑定记录失败", deleteErr)
	}

	s.auditUnbind(ctx, input, identity, true, 0)
	return &UnbindIdentityResult{
		Provider:   string(identity.Provider),
		ProviderID: identity.ProviderID,
	}, nil
}

// hasOtherLoginMethod reports whether the user keeps a usable login method once
// the identity with excludeID is gone. A login email always qualifies; otherwise
// at least one other identity must remain.
func hasOtherLoginMethod(user *model.User, excludeID int64) bool {
	if strings.TrimSpace(user.LoginEmail) != "" {
		return true
	}
	for _, identity := range user.Identities {
		if identity.ID != excludeID {
			return true
		}
	}
	return false
}

// releaseUnbindCooldown drops a claim whose unbind did not land.
//
// It deliberately detaches from the caller's context. The most likely reason the
// delete failed is that ctx was cancelled — a disconnected client or an expired
// deadline — and go-redis refuses to acquire a connection on a cancelled context,
// so reusing ctx here would make the release a no-op in exactly the case it
// exists for, holding the address for the rest of the window over an unbind that
// never happened. Same shape as the login compensation path.
func (s Service) releaseUnbindCooldown(ctx context.Context, subject string) {
	if s.UnbindCooldowns == nil {
		return
	}
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cooldownReleaseTimeout)
	defer cancel()
	if err := s.UnbindCooldowns.Release(releaseCtx, subject); err != nil {
		slog.WarnContext(ctx, "release unbind cooldown after failed unbind", "error", err)
	}
}

func (s Service) auditUnbind(ctx context.Context, input UnbindIdentityInput, identity *model.Identity, success bool, errCode int) {
	detail := map[string]any{
		"provider":    string(identity.Provider),
		"provider_id": identity.ProviderID,
	}
	id := strconv.FormatInt(identity.ID, 10)
	if err := s.audit(ctx, &input.UserID, "oauth_unbind", "identity", &id, success, errCode,
		input.ClientIP, input.UserAgent, detail); err != nil {
		slog.Error("audit oauth unbind", "user_id", input.UserID, "identity_id", identity.ID, "error", err)
	}
}
