package oauthlogin

import (
	"context"
	"errors"
	"log/slog"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// Bind attaches a provider account to the authenticated caller.
//
// This is the only path by which an existing account gains a third-party
// binding. A registration_state must never be accepted here: it proves that
// somebody completed a provider callback, not which account is acting, so
// honouring it would let a leaked state bind an attacker's GitHub to a victim's
// account. The caller is identified by their Bearer token and nothing else.
//
// No OAuth state is involved: the caller passes the provider code directly and
// the request is already authenticated, so there is no cross-site request to
// protect against.
func (s Service) Bind(ctx context.Context, input BindInput) (*BindResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidInput, "身份主体无效", nil)
	}
	if input.Code == "" {
		return nil, newError(ErrInvalidInput, "code 不能为空", nil)
	}
	client, err := s.providerClient(input.Provider)
	if err != nil {
		return nil, err
	}

	user, err := s.Users.FindAuthUserByID(ctx, input.UserID)
	if err != nil {
		if isNotFound(err) {
			return nil, newError(ErrUserNotFound, "用户不存在", err)
		}
		return nil, newError(ErrInternal, "查询用户失败", err)
	}
	if user.State == model.UserStateDeleted {
		return nil, newError(ErrUserDeleted, "账号已注销", nil)
	}

	identity, err := client.Exchange(ctx, input.Code, input.RedirectURI)
	if err != nil {
		return nil, providerError(err)
	}

	// Check for an existing owner before inserting so "someone else has it"
	// (40903) is told apart from "you already have one" (40904); a bare
	// constraint violation cannot.
	existing, err := s.Identities.FindByProviderID(ctx, input.Provider, identity.ProviderID)
	if err != nil && !isNotFound(err) {
		return nil, newError(ErrInternal, "查询第三方绑定失败", err)
	}
	if existing != nil {
		if existing.UserID == input.UserID {
			// Already bound to this same caller: refresh the stored credentials so a
			// re-bind is idempotent, then report the conflict, since this provider caps
			// at one row per user.
			if updateErr := s.Identities.UpdateProviderCredentials(ctx, existing.ID,
				credentialUpdate(ctx, identity)); updateErr != nil {
				slog.WarnContext(ctx, "refresh identity on repeated bind",
					"identity_id", existing.ID, "error", updateErr)
			}
			s.auditBind(ctx, input, identity.ProviderID, false, ErrIdentityAlreadyBound.Code)
			return nil, newError(ErrIdentityAlreadyBound, "该类型账号已绑定，不可重复绑定", nil)
		}
		s.auditBind(ctx, input, identity.ProviderID, false, ErrIdentityOccupied.Code)
		return nil, newError(ErrIdentityOccupied, "该第三方账号已被其他用户绑定", nil)
	}

	row := &model.Identity{
		UserID:         input.UserID,
		Provider:       input.Provider,
		ProviderID:     identity.ProviderID,
		IdentityData:   identityJSONB(ctx, identity.Data),
		AccessToken:    nonEmpty(identity.AccessToken),
		RefreshToken:   nonEmpty(identity.RefreshToken),
		TokenExpiresAt: identity.TokenExpiresAt,
	}
	if err := s.Identities.CreateWithinLimit(ctx, row, providerIdentityLimit); err != nil {
		return nil, s.bindWriteError(ctx, input, identity.ProviderID, err)
	}

	s.auditBind(ctx, input, identity.ProviderID, true, 0)
	return &BindResult{Identity: *row}, nil
}

// bindWriteError maps an insert failure onto the right conflict code.
//
// The pre-check above can be raced: two concurrent binds both see no owner, and
// the loser lands here, so the mapping must dispatch on the constraint rather
// than report generically.
func (s Service) bindWriteError(
	ctx context.Context,
	input BindInput,
	providerID string,
	err error,
) error {
	switch {
	case errors.Is(err, repository.ErrLimitExceeded):
		// The user already holds this provider's single allowed binding.
		s.auditBind(ctx, input, providerID, false, ErrIdentityAlreadyBound.Code)
		return newError(ErrIdentityAlreadyBound, "该类型账号已绑定，不可重复绑定", err)
	case errors.Is(err, repository.ErrNotFound):
		return newError(ErrUserNotFound, "用户不存在", err)
	default:
		switch constraint := duplicateConstraint(err); constraint {
		case identityProviderConstraint:
			// Lost the race on (provider, provider_id): another user bound this account
			// between the pre-check and the insert.
			s.auditBind(ctx, input, providerID, false, ErrIdentityOccupied.Code)
			return newError(ErrIdentityOccupied, "该第三方账号已被其他用户绑定", err)
		case identityUserGitHubConstraint, identityUserLarkConstraint:
			// Lost the race on the per-user partial unique index: a concurrent request
			// bound this same provider to this same caller.
			s.auditBind(ctx, input, providerID, false, ErrIdentityAlreadyBound.Code)
			return newError(ErrIdentityAlreadyBound, "该类型账号已绑定，不可重复绑定", err)
		case "":
			return newError(ErrInternal, "创建第三方绑定失败", err)
		default:
			// An unmapped unique constraint; report a generic conflict and log the name
			// so the mapping can be extended.
			slog.ErrorContext(ctx, "unmapped unique violation on oauth bind",
				"constraint", constraint, "provider", string(input.Provider))
			return newError(ErrIdentityOccupied, "第三方绑定与现有记录冲突", err)
		}
	}
}

// PostgreSQL's unique-index names for the identities table, from V001. They
// map to different business codes: the global (provider, provider_id) index
// means somebody else owns the account (40903), while the per-user partial
// indexes mean the caller already has one (40904).
const (
	identityProviderConstraint   = "uq_identities_provider_provider_id"
	identityUserGitHubConstraint = "uq_identities_user_github"
	identityUserLarkConstraint   = "uq_identities_user_lark"
)

// duplicateConstraint returns the violated unique constraint's name, or "" when
// err is not a unique violation; it wraps the repository helper so the
// classification exists once.
func duplicateConstraint(err error) string {
	return repository.DuplicateConstraint(err)
}

func (s Service) auditBind(
	ctx context.Context,
	input BindInput,
	providerID string,
	success bool,
	errCode int,
) {
	detail := map[string]any{
		"provider":    string(input.Provider),
		"provider_id": providerID,
	}
	if err := s.audit(ctx, &input.UserID, "oauth_bind", "identity", nil, success, errCode, input.ActorClientID,
		input.ClientIP, input.UserAgent, detail); err != nil {
		logAuditFailure(ctx, "oauth_bind", err)
	}
}

// logAuditFailure records an audit write failure. Audit rows are a trail, not a
// gate: losing one must not fail the request, but it must be visible.
func logAuditFailure(ctx context.Context, action string, err error) {
	slog.ErrorContext(ctx, "audit write failed", "action", action, "error", err)
}
