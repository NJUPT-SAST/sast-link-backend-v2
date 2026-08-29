package oauthlogin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/provider"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/shared"
)

// providerIdentity aliases the provider package's normalized identity so this
// package's signatures do not repeat the import path.
type providerIdentity = provider.Identity

// auditTimeout bounds the detached audit write; the row must survive the caller
// going away, but a stuck database must not hold a login callback hostage.
const auditTimeout = 5 * time.Second

// providerClient resolves an enabled provider, or reports that this deployment
// does not offer it.
func (s Service) providerClient(name model.LoginMethod) (ProviderClient, error) {
	client, ok := s.Providers[name]
	if !ok || client == nil {
		return nil, newError(ErrInvalidInput, "不支持的第三方登录方式", nil)
	}
	return client, nil
}

// stateDigest is the login-CSRF cookie value for a state: hex(SHA-256(state)).
// The state is high-entropy, so a bare digest suffices — the cookie proves the
// callback browser started the authorization rather than hiding the state.
func stateDigest(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

// stateDigestMatches compares a state against a cookie value in constant time,
// so a mismatch leaks nothing about the digest.
func stateDigestMatches(state, cookieValue string) bool {
	expected := stateDigest(state)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(cookieValue)) == 1
}

// resolveRedirect validates a requested frontend redirect against the
// allow-list.
//
// Exact match only: a prefix rule would admit https://link.sast.fun.evil.test
// and hand a live login_code to whatever it redirects to.
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
//
// The restart-the-login outcomes carry display messages because they share
// KindInvalidState with a genuinely expired state, whose default string would
// send the user looking for a fault in a valid state.
func providerError(err error) error {
	switch {
	case errors.Is(err, provider.ErrForeignTenant):
		return newError(ErrForeignTenant, "仅限 SAST 成员登录", err)
	case errors.Is(err, provider.ErrInvalidGrant):
		// The only input the user controls is the code their browser carried, so
		// this is a restart-the-login outcome, not a server fault.
		return newDisplayError(ErrStateInvalid, "第三方授权码无效或已过期", err)
	case errors.Is(err, context.DeadlineExceeded):
		// The provider accepted the connection and then did not answer within
		// httpIOTimeout — a single slow round trip is not evidence the provider is
		// down, so this is a restartable failure.
		return newDisplayError(ErrStateInvalid, "连接第三方登录服务超时", err)
	case errors.Is(err, context.Canceled):
		// The caller went away mid-exchange; reporting a provider outage would blame
		// the provider for a client disconnect.
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

// auditErrorCode extracts the business error code carried by a service *Error,
// falling back to the internal code for wrapped or plain errors.
func auditErrorCode(err error) int {
	var serviceErr *Error
	if errors.As(err, &serviceErr) {
		return serviceErr.Code
	}
	return errcode.CodeInternal
}

func (s Service) now() time.Time {
	clock := s.Clock
	if clock == nil {
		clock = auth.SystemClock
	}
	return clock.Now().UTC()
}

// audit writes one audit row; failures never fail the caller's flow and are
// logged by the caller. It mirrors session.Service.audit so both services
// produce identically shaped rows.
func (s Service) audit(
	ctx context.Context,
	userID *int64,
	action string,
	resource string,
	resourceID *string,
	success bool,
	errCode int,
	actorClientID string,
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
	// Detached context: an audit row for a completed action must survive the
	// caller going away, or an aborted callback's events vanish from the log.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	return s.Audits.Create(auditCtx, &model.AuditLog{
		UserID:     userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Detail:     detailValue,
		ClientIP:   clientIPPtr,
		UserAgent:  userAgentPtr,
		Success:    &successValue,
		ErrCode:    errCodePtr,
		// The acting client, or the built-in console client for an internal
		// session: an authenticated bind is not an unauthenticated action, so
		// NULL here must stay unambiguous.
		ActorClientID: shared.NullableString(shared.ActorClientID(actorClientID, s.InternalClientID)),
		CreatedAt:     s.now(),
	})
}

// identityJSONB encodes a provider metadata map for the identity_data column;
// model.JSONB is raw JSON, so the map is marshalled. A failure yields nil
// (NULL column), losing display metadata rather than failing a login.
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
	if err := s.audit(ctx, userID, "oauth_login", "session", nil, success, errCode, "",
		input.ClientIP, input.UserAgent, detail); err != nil {
		logAuditFailure(ctx, "oauth_login", err)
	}
}
