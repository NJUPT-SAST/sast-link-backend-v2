package oauthlogin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/provider"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// providerIdentity aliases the provider package's normalized identity so this
// package's signatures do not repeat the import path.
type providerIdentity = provider.Identity

// providerClient resolves an enabled provider, or reports that this deployment
// does not offer it.
func (s Service) providerClient(name model.LoginMethod) (ProviderClient, error) {
	client, ok := s.Providers[name]
	if !ok || client == nil {
		return nil, newError(ErrInvalidInput, "不支持的第三方登录方式", nil)
	}
	return client, nil
}

// resolveRedirect validates a requested frontend redirect against the
// allow-list.
//
// Exact match only. A prefix or suffix rule is what turns an allow-list into an
// open redirect: "starts with https://link.sast.fun" also admits
// https://link.sast.fun.evil.test, and the callback hands a login_code to
// whatever it redirects to.
func (s Service) resolveRedirect(requested string) (string, error) {
	if requested == "" {
		return s.DefaultRedirect, nil
	}
	for _, allowed := range s.AllowedRedirects {
		if requested == allowed {
			return requested, nil
		}
	}
	return "", newError(ErrInvalidInput, "redirect 不在允许列表中", nil)
}

// providerError maps an outbound provider failure onto a business outcome.
func providerError(err error) error {
	switch {
	case errors.Is(err, provider.ErrForeignTenant):
		return newError(ErrForeignTenant, "仅限 SAST 成员登录", err)
	case errors.Is(err, provider.ErrInvalidGrant):
		// The only input the user controls is the code their browser carried, so
		// this is a restart-the-login outcome, not a server fault.
		return newError(ErrStateInvalid, "第三方授权码无效或已过期", err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// The caller went away mid-exchange. Reporting a provider outage would
		// blame GitHub or Lark for a client disconnect.
		return newError(ErrDependencyUnavailable, "第三方授权请求被中断", err)
	default:
		return newError(ErrProviderUnavailable, "第三方服务暂时不可用", err)
	}
}

// isNotFound reports whether err is the repository's missing-row sentinel.
func isNotFound(err error) bool {
	return errors.Is(err, repository.ErrNotFound)
}

// credentialUpdate projects a provider identity onto the columns a re-login
// refreshes.
func credentialUpdate(ctx context.Context, identity *providerIdentity) repository.IdentityCredentialUpdate {
	return repository.IdentityCredentialUpdate{
		IdentityData:   identityJSONB(ctx, identity.Data),
		AccessToken:    nonEmpty(identity.AccessToken),
		RefreshToken:   nonEmpty(identity.RefreshToken),
		TokenExpiresAt: identity.TokenExpiresAt,
	}
}

func (s Service) now() time.Time {
	clock := s.Clock
	if clock == nil {
		clock = auth.SystemClock
	}
	return clock.Now().UTC()
}

// audit writes one audit row. Audit failures never fail the caller's flow; the
// caller logs them. Mirrors session.Service.audit so both services produce
// identically shaped rows, including the resourceID the session service carries
// on evict_device rows — a third-party login eviction must leave the same trail
// as a password-login one.
func (s Service) audit(
	ctx context.Context,
	userID *int64,
	action string,
	resource string,
	resourceID *string,
	success bool,
	errCode int,
	clientIP string,
	userAgent string,
	detail map[string]any,
) error {
	if s.Audits == nil {
		return nil
	}
	var detailValue model.JSONB
	if detail != nil {
		encoded, err := json.Marshal(detail)
		if err != nil {
			return fmt.Errorf("marshal audit detail: %w", err)
		}
		detailValue = model.JSONB(encoded)
	}
	var errCodePtr *int
	if errCode != 0 {
		errCodePtr = &errCode
	}
	var clientIPPtr *string
	if strings.TrimSpace(clientIP) != "" {
		clientIPPtr = &clientIP
	}
	var userAgentPtr *string
	if strings.TrimSpace(userAgent) != "" {
		userAgentPtr = &userAgent
	}
	successValue := success
	return s.Audits.Create(ctx, &model.AuditLog{
		UserID:     userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Detail:     detailValue,
		ClientIP:   clientIPPtr,
		UserAgent:  userAgentPtr,
		Success:    &successValue,
		ErrCode:    errCodePtr,
		CreatedAt:  s.now(),
	})
}

// identityJSONB encodes a provider's metadata map for the identity_data column.
// model.JSONB is raw JSON, not a map, so the map has to be marshalled rather
// than converted. A marshal failure yields nil, which leaves the column NULL —
// losing display metadata is preferable to failing a login over it.
func identityJSONB(ctx context.Context, data map[string]any) model.JSONB {
	if len(data) == 0 {
		return nil
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		slog.WarnContext(ctx, "marshal provider identity_data", "error", err)
		return nil
	}
	return model.JSONB(encoded)
}

// auditLogin records an oauth_login attempt. The detail names the provider and
// the provider-side account so a support request can be traced without joining
// against the identities table.
func (s Service) auditLogin(
	ctx context.Context,
	userID *int64,
	input CallbackInput,
	success bool,
	errCode int,
	providerID string,
) {
	detail := map[string]any{
		"provider":    string(input.Provider),
		"provider_id": providerID,
	}
	if err := s.audit(ctx, userID, "oauth_login", "session", nil, success, errCode,
		input.ClientIP, input.UserAgent, detail); err != nil {
		logAuditFailure(ctx, "oauth_login", err)
	}
}
