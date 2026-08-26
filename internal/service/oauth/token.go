package oauth

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/tokenissue"
)

// clientAuthFailed is the single description every client authentication failure
// returns, so a future branch cannot reintroduce a distinguishable message.
const clientAuthFailed = "客户端认证失败"

// Token implements RFC 6749 §4.1.3 and §6 for the two supported grants.
func (s Service) Token(ctx context.Context, input TokenInput) (*TokenResult, error) {
	// Throttled before the grant is dispatched, so a caller cannot spend an
	// unlimited number of client_secret or refresh_token guesses, each costing a DB
	// round trip.
	if err := s.checkTokenLimit(ctx, input.ClientIP); err != nil {
		return nil, err
	}
	switch strings.TrimSpace(input.GrantType) {
	case grantTypeAuthorizationCode:
		return s.tokenByAuthorizationCode(ctx, input)
	case grantTypeRefreshToken:
		return s.tokenByRefreshToken(ctx, input)
	case "":
		return nil, newError(ErrInvalidRequest, "grant_type 不能为空", nil)
	default:
		return nil, newError(ErrUnsupportedGrantType, "仅支持 authorization_code 与 refresh_token", nil)
	}
}

// tokenByAuthorizationCode redeems an authorization code for a token pair.
//
// Order matters: the client is authenticated first, then the code is consumed,
// and only then are its bindings checked. Consuming before the bindings are
// verified is deliberate — the code is single-use, so a failed PKCE attempt must
// still burn it, or an attacker holding a stolen code could probe verifiers
// indefinitely against a code that stays live.
func (s Service) tokenByAuthorizationCode(ctx context.Context, input TokenInput) (*TokenResult, error) {
	client, err := s.authenticateClient(ctx, input.ClientID, input.ClientSecret)
	if err != nil {
		// Audit client-authentication failures too — a client_secret sweep against
		// the token endpoint must not be indistinguishable from silence.
		s.auditToken(ctx, nil, input.ClientID, grantTypeAuthorizationCode, input, false, errcode.CodeUnauthenticated, "client_auth_failed")
		return nil, err
	}
	if !slices.Contains([]string(client.GrantTypes), grantTypeAuthorizationCode) {
		return nil, newError(ErrUnauthorizedClient, "客户端未获授权使用 authorization_code", nil)
	}
	code := strings.TrimSpace(input.Code)
	if code == "" {
		return nil, newError(ErrInvalidRequest, "code 不能为空", nil)
	}
	verifier := strings.TrimSpace(input.CodeVerifier)
	if verifier == "" {
		return nil, newError(ErrInvalidRequest, "code_verifier 不能为空", nil)
	}

	authorization, consumedVersion, consumeErr := s.Authorizations.Consume(ctx, code, s.now())
	switch {
	case errors.Is(consumeErr, repository.ErrNotFound):
		return nil, newError(ErrInvalidGrant, "授权码无效", nil)
	case errors.Is(consumeErr, repository.ErrAuthorizationReplayed):
		// The code must belong to the authenticated client before its family is cut,
		// or any authenticated client holding another client's spent code could
		// revoke that client's family. A mismatch answers as a plain invalid_grant,
		// the same as an unknown code, revealing nothing either way.
		if authorization == nil || authorization.ClientID != client.ID {
			return nil, newError(ErrInvalidGrant, "授权码无效", nil)
		}
		// PRD §4.10: a replayed code means it leaked, so cut the whole family.
		if authorization.FamilyID != nil {
			s.revokeFamily(ctx, *authorization.FamilyID)
		} else {
			// family_id is nullable and Consent always sets it, so this is a row this
			// service did not mint; the replay must not pass silently since there is
			// nothing to cut.
			slog.ErrorContext(ctx, "replayed authorization code has no family to revoke",
				"client_id", client.ClientID)
		}
		s.auditToken(ctx, nil, client.ClientID, grantTypeAuthorizationCode, input, false, errcode.CodeAccessTokenInvalid, "code_replayed")
		return nil, newError(ErrInvalidGrant, "授权码无效", nil)
	case errors.Is(consumeErr, repository.ErrAuthorizationExpired):
		return nil, newError(ErrInvalidGrant, "授权码已过期", nil)
	case consumeErr != nil:
		return nil, newError(ErrInternal, "消费授权码失败", consumeErr)
	}

	// The code must belong to the authenticated client, or a client could redeem a
	// code issued to someone else. The description stays the same "授权码无效" as an
	// unknown code so this endpoint is not an oracle; the wrapped error records the
	// mismatch for operators.
	if authorization.ClientID != client.ID {
		return nil, newError(ErrInvalidGrant, "授权码无效",
			errors.New("authorization code belongs to a different client"))
	}
	// RFC 6749 §4.1.3 requires redirect_uri to match the authorization request.
	if redirectErr := matchRedirectURI(authorization.RedirectURI, input.RedirectURI); redirectErr != nil {
		return nil, redirectErr
	}
	if pkceErr := auth.VerifyPKCES256(verifier, authorization.CodeChallenge, authorization.CodeChallengeMethod); pkceErr != nil {
		return nil, newError(ErrInvalidGrant, "code_verifier 校验失败", pkceErr)
	}

	user, err := s.Users.FindAuthUserByID(ctx, authorization.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidGrant, "授权码所属用户无效", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询授权码所属用户失败", err)
	}
	if user.State == model.UserStateDeleted {
		return nil, newError(ErrInvalidGrant, "账号已注销", nil)
	}
	// A bulk revocation (password change, demotion, account close) bumps
	// token_version in the same transaction that cuts tokens. If it moved since the
	// consume, issuing now would mint a session the revocation never saw; the write
	// below re-checks under the user row lock, so this early exit only skips work.
	if user.TokenVersion != int(consumedVersion) {
		s.auditToken(ctx, nil, client.ClientID, grantTypeAuthorizationCode, input, false, errcode.CodeAccessTokenInvalid, "code_redeemed_after_revocation")
		return nil, newError(ErrInvalidGrant, "授权码已失效，请重新发起授权",
			errors.New("user token version changed since code consume"))
	}

	// Scopes are re-checked against the live registration, the same re-check Consent
	// applies to a stash: without it, revoking a client's admin scope would leave
	// every outstanding code redeemable for an administrative token until it expires.
	// Checked after the consume, so a rejection here still burns the code.
	if scopeErr := checkScopeForClient(client, []string(authorization.Scopes)); scopeErr != nil {
		return nil, newError(ErrInvalidScope, "scope 已不在客户端注册范围内，请重新发起授权", scopeErr)
	}

	scopes := []string(authorization.Scopes)
	familyID := ""
	if authorization.FamilyID != nil {
		familyID = *authorization.FamilyID
	}
	// A capability family's first refresh token is born at this moment, so its
	// expiry is its lifetime cap: the rotation leg later clamps every refresh to
	// origin+cap, and clamping here keeps the very first token inside it too.
	// The access token is clamped the same way, or a redemption at the cap's edge
	// would carry a full access TTL past the delegation's boundary.
	refreshTTL := s.refreshTTL()
	accessTTL := s.accessTTL()
	if lifetime := s.capabilityRefreshLifetime(scopes); lifetime > 0 && lifetime < refreshTTL {
		refreshTTL = lifetime
		if accessTTL > lifetime {
			accessTTL = lifetime
		}
	}
	pair, err := s.issuer().Issue(tokenissue.Request{
		User:       user,
		Client:     client,
		Sequence:   0,
		FamilyID:   familyID,
		Scopes:     scopes,
		AccessTTL:  accessTTL,
		RefreshTTL: refreshTTL,
	})
	if err != nil {
		return nil, newError(ErrInternal, "签发 Token Pair 失败", err)
	}
	// The success audit rides the token transaction; a build failure logs and drops
	// the row — there is no synchronous fallback for the success path.
	var codeAudit *model.AuditLog
	if s.Audit != nil {
		resourceID := client.ClientID
		codeAudit, err = s.buildAuditEntry(&user.ID, "oauth_token", &resourceID, &resourceID, true, 0,
			input.ClientIP, input.UserAgent, map[string]any{
				"client_id":  client.ClientID,
				"grant_type": grantTypeAuthorizationCode,
				"outcome":    "issued",
			})
		if err != nil {
			slog.WarnContext(ctx, "build oauth code audit entry", "error", err)
			codeAudit = nil
		}
	}
	if createErr := s.Tokens.CreatePairWithUserAndClientLock(ctx, user.ID, client.ID, consumedVersion, pair.Access, pair.Refresh, codeAudit); createErr != nil {
		if errors.Is(createErr, repository.ErrUserStateChanged) || errors.Is(createErr, repository.ErrClientInactive) ||
			errors.Is(createErr, repository.ErrClientScopeChanged) || errors.Is(createErr, repository.ErrNotFound) {
			// A revocation landed between the consume and this write: the pair must not
			// be minted, and the answer matches an unknown code so the endpoint stays
			// non-oracular.
			s.auditToken(ctx, nil, client.ClientID, grantTypeAuthorizationCode, input, false, errcode.CodeAccessTokenInvalid, "code_redeemed_after_revocation")
			return nil, newError(ErrInvalidGrant, "授权码已失效，请重新发起授权", createErr)
		}
		return nil, newError(ErrInternal, "持久化 Token Pair 失败", createErr)
	}

	nonce := ""
	if authorization.Nonce != nil {
		nonce = *authorization.Nonce
	}
	// auth_time is the code's creation instant, which in this flow is exactly when
	// the user confirmed the authorization: Consent creates the row on approval.
	idToken, err := s.signIDToken(ctx, user, client, scopes, nonce, authorization.CreatedAt)
	if err != nil {
		// The pair is already persisted, so a signing failure must not leave a live
		// session the client never learned about.
		s.revokeFamily(ctx, pair.FamilyID)
		return nil, err
	}

	return s.tokenResult(pair, idToken), nil
}

// tokenByRefreshToken rotates a refresh token, per RFC 6749 §6.
func (s Service) tokenByRefreshToken(ctx context.Context, input TokenInput) (*TokenResult, error) {
	client, err := s.authenticateClient(ctx, input.ClientID, input.ClientSecret)
	if err != nil {
		s.auditToken(ctx, nil, input.ClientID, grantTypeRefreshToken, input, false, errcode.CodeUnauthenticated, "client_auth_failed")
		return nil, err
	}
	if !slices.Contains([]string(client.GrantTypes), grantTypeRefreshToken) {
		return nil, newError(ErrUnauthorizedClient, "客户端未获授权使用 refresh_token", nil)
	}
	presented := strings.TrimSpace(input.RefreshToken)
	if presented == "" {
		return nil, newError(ErrInvalidRequest, "refresh_token 不能为空", nil)
	}

	tokenHash, err := s.RefreshTokens.HashRefreshToken(presented)
	if err != nil {
		// A token not shaped like ours reports invalid_grant, indistinguishable from an
		// unknown one.
		return nil, newError(ErrInvalidGrant, "refresh_token 无效", err)
	}
	current, err := s.Tokens.FindRefreshToken(ctx, tokenHash)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidGrant, "refresh_token 无效", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询 refresh_token 失败", err)
	}

	// The token must belong to the authenticated client; this also keeps the OAuth
	// path and the internal session path from crossing, since a session token belongs
	// to the built-in client. The description stays the same "refresh_token 无效" as an
	// unknown token so this endpoint is not an oracle; the wrapped error records the
	// mismatch for operators.
	if current.ClientID != client.ID {
		return nil, newError(ErrInvalidGrant, "refresh_token 无效",
			errors.New("refresh token belongs to a different client"))
	}
	if current.RevokedAt != nil {
		// The token was rotated or cancelled by another request in this family: within
		// the grace window that is a benign concurrent refresh that must not re-revoke,
		// or it would log out the winner; beyond it, a true replay whose family is cut.
		if !repository.IsWithinRefreshGrace(*current.RevokedAt, s.now()) {
			// A true replay of a long-dead token: cut the family.
			s.revokeFamily(ctx, current.FamilyID)
			s.auditToken(ctx, &current.UserID, client.ClientID, grantTypeRefreshToken, input, false, errcode.CodeAccessTokenInvalid, "refresh_replayed")
		} else {
			// A benign concurrent refresh within the grace window: report invalid
			// without cutting, audited distinctly from a replay (matching the session
			// path's concurrent_refresh).
			s.auditToken(ctx, &current.UserID, client.ClientID, grantTypeRefreshToken, input, false, errcode.CodeAccessTokenInvalid, "concurrent_refresh")
		}
		return nil, newError(ErrInvalidGrant, "refresh_token 无效", nil)
	}
	if !current.ExpiresAt.After(s.now()) {
		return nil, newError(ErrInvalidGrant, "refresh_token 已过期", nil)
	}

	user, err := s.Users.FindAuthUserByID(ctx, current.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidGrant, "refresh_token 所属用户无效", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询 refresh_token 所属用户失败", err)
	}
	if user.State == model.UserStateDeleted {
		return nil, newError(ErrInvalidGrant, "账号已注销", nil)
	}

	// Scope narrowing (RFC 6749 §6) is not supported: rotated pairs carry exactly
	// the current scopes unchanged; a client wanting fewer must re-authorize.
	scopes := []string(current.Scopes)
	// Defense-in-depth mirroring the redemption leg: a change that did not go through
	// the revoking update would otherwise let the family keep minting access tokens
	// for a scope the registration no longer holds. The revoking update normally cuts
	// the family first, so this is a backstop.
	if scopeErr := checkScopeForClient(client, scopes); scopeErr != nil {
		return nil, newError(ErrInvalidScope, "scope 已不在客户端注册范围内，请重新发起授权", scopeErr)
	}
	pair, err := s.issuer().Issue(tokenissue.Request{
		User:       user,
		Client:     client,
		Sequence:   current.Sequence + 1,
		FamilyID:   current.FamilyID,
		Scopes:     scopes,
		AccessTTL:  s.accessTTL(),
		RefreshTTL: s.refreshTTL(),
	})
	if err != nil {
		return nil, newError(ErrInternal, "签发 Token Pair 失败", err)
	}
	// A rotation is not a fresh authentication, so auth_time stays the family
	// origin: the sequence-0 row's creation time, read inside the rotation
	// transaction. Reading current.CreatedAt would advance it with every rotation.
	// The success audit rides the rotation transaction; a build failure logs and
	// drops the row.
	var refreshAudit *model.AuditLog
	if s.Audit != nil {
		resourceID := client.ClientID
		refreshAudit, err = s.buildAuditEntry(&user.ID, "oauth_token", &resourceID, &resourceID, true, 0,
			input.ClientIP, input.UserAgent, map[string]any{
				"client_id":  client.ClientID,
				"grant_type": grantTypeRefreshToken,
				"outcome":    "rotated",
			})
		if err != nil {
			slog.WarnContext(ctx, "build oauth refresh audit entry", "error", err)
			refreshAudit = nil
		}
	}
	authTime, rotateErr := s.Tokens.RotateRefreshTokenWithAuditCapped(
		ctx, current.FamilyID, tokenHash, pair.Access, pair.Refresh, refreshAudit,
		s.capabilityRefreshLifetime(scopes),
	)
	if rotateErr != nil {
		if errors.Is(rotateErr, repository.ErrTokenReplayWithinGrace) {
			// The rotation transaction preserved the family for a benign concurrent
			// refresh; re-revoking would log out the winner. Audited as
			// concurrent_refresh, not a replay.
			s.auditToken(ctx, &user.ID, client.ClientID, grantTypeRefreshToken, input, false, errcode.CodeAccessTokenInvalid, "concurrent_refresh")
			return nil, newError(ErrInvalidGrant, "refresh_token 无效", rotateErr)
		}
		if errors.Is(rotateErr, repository.ErrTokenReplay) ||
			errors.Is(rotateErr, repository.ErrTokenExpired) ||
			errors.Is(rotateErr, repository.ErrTokenFamilyRevoked) {
			// A true replay: the rotation transaction already cut the family, so
			// report invalid without re-revoking. Audited as a replay.
			s.auditToken(ctx, &user.ID, client.ClientID, grantTypeRefreshToken, input, false, errcode.CodeAccessTokenInvalid, "refresh_replayed")
			return nil, newError(ErrInvalidGrant, "refresh_token 无效", rotateErr)
		}
		if errors.Is(rotateErr, repository.ErrTokenFamilyExpired) {
			// The family reached its capability lifetime cap and the rotation
			// transaction revoked it, so the client must re-authorize. Audited
			// distinctly from a replay.
			s.auditToken(ctx, &user.ID, client.ClientID, grantTypeRefreshToken, input, false, errcode.CodeAccessTokenInvalid, "refresh_family_expired")
			return nil, newError(ErrInvalidGrant, "refresh_token 已超过最长有效期，请重新授权", rotateErr)
		}
		return nil, newError(ErrInternal, "轮换 refresh_token 失败", rotateErr)
	}
	idToken, err := s.signIDToken(ctx, user, client, scopes, "", authTime)
	if err != nil {
		s.revokeFamily(ctx, pair.FamilyID)
		return nil, err
	}

	return s.tokenResult(pair, idToken), nil
}

// authenticateClient resolves and authenticates the requesting client.
//
// A public client (no stored secret) authenticates by PKCE alone, which the caller
// verifies against the authorization code; a confidential client must present a
// matching client_secret. A public client that sends a secret anyway is rejected
// rather than ignored, so a misconfiguration about its own type is surfaced.
//
// Every rejection answers with the same description on purpose: distinct wording
// would make this endpoint an oracle for a known client_id, telling a caller
// whether the client exists and whether it is public or confidential. client_id is
// public by design, so what needs protecting is the client's configuration.
// Authorize holds the same line, and the wrapped error plus audit log preserve the
// specific cause for operators.
func (s Service) authenticateClient(ctx context.Context, clientID, clientSecret string) (*model.OAuthClient, error) {
	id := strings.TrimSpace(clientID)
	if id == "" {
		return nil, newError(ErrInvalidClient, "client_id 不能为空", nil)
	}
	client, err := s.Clients.FindActiveByClientID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInvalidArgument) {
		return nil, newError(ErrInvalidClient, clientAuthFailed, err)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询 OAuth 客户端失败", err)
	}

	presented := strings.TrimSpace(clientSecret)
	if client.ClientSecretHash == nil {
		if presented != "" {
			return nil, newError(ErrInvalidClient, clientAuthFailed,
				errors.New("public client presented a client_secret"))
		}
		return client, nil
	}
	if presented == "" {
		return nil, newError(ErrInvalidClient, clientAuthFailed,
			errors.New("confidential client omitted its client_secret"))
	}
	if err := auth.VerifyClientSecret(presented, *client.ClientSecretHash); err != nil {
		return nil, newError(ErrInvalidClient, clientAuthFailed, err)
	}
	return client, nil
}

// matchRedirectURI enforces the RFC 6749 §4.1.3 redirect_uri check.
func matchRedirectURI(authorized *string, presented string) error {
	value := strings.TrimSpace(presented)
	if authorized == nil || *authorized == "" {
		// Every code issued stores its redirect_uri, so a missing one was not written
		// by Consent.
		return newError(ErrInvalidGrant, "授权码缺少 redirect_uri", nil)
	}
	if value == "" {
		return newError(ErrInvalidRequest, "redirect_uri 不能为空", nil)
	}
	if value != *authorized {
		return newError(ErrInvalidGrant, "redirect_uri 与授权请求不一致", nil)
	}
	return nil
}

// signIDToken builds the ID Token for a granted scope set.
//
// authTime is the moment the user approved the authorization, which is NOT what
// OIDC means by auth_time (when the end user authenticated): nothing records an
// authentication instant yet, so the value overstates recency. The claim is kept
// out of claims_supported for that reason — see Discovery.
func (s Service) signIDToken(
	ctx context.Context,
	user *model.User,
	client *model.OAuthClient,
	scopes []string,
	nonce string,
	authTime time.Time,
) (string, error) {
	claims, err := s.idTokenClaims(ctx, user, scopes)
	if err != nil {
		return "", err
	}
	idToken, err := s.JWT.SignIDToken(auth.IDTokenInput{
		Subject:  userIDString(user.ID),
		ClientID: client.ClientID,
		Scopes:   scopes,
		Nonce:    nonce,
		AuthTime: authTime,
		TTL:      s.accessTTL(),
		Claims:   claims,
	})
	if err != nil {
		return "", newError(ErrInternal, "签发 ID Token 失败", err)
	}
	return idToken, nil
}

func (s Service) tokenResult(pair *tokenissue.Pair, idToken string) *TokenResult {
	return &TokenResult{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    BearerTokenType,
		ExpiresIn:    int(math.Ceil(s.accessTTL().Seconds())),
		Scope:        pair.ScopeClaim,
		IDToken:      idToken,
	}
}

func (s Service) auditToken(
	ctx context.Context,
	userID *int64,
	clientID, grantType string,
	input TokenInput,
	success bool,
	errCode int,
	outcome string,
) {
	resourceID := clientID
	s.audit(ctx, userID, "oauth_token", &resourceID, success, errCode, input.ClientIP, input.UserAgent, map[string]any{
		"client_id":  clientID,
		"grant_type": grantType,
		"outcome":    outcome,
	})
}
