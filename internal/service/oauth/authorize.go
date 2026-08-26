package oauth

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

const (
	responseTypeCode           = "code"
	grantTypeAuthorizationCode = "authorization_code"
	grantTypeRefreshToken      = "refresh_token"
	pkceMethodS256             = "S256"

	// maxAuthorizeParameterLength bounds the free-form authorize parameters that are
	// persisted with the code, matching oauth_authorizations.code_challenge and .nonce
	// (V001). Refusing an oversized value here keeps it from failing later at consent,
	// after the single-use stash has been spent.
	maxAuthorizeParameterLength = 255
	// maxStateLength bounds the state echoed back to the client; it is held in the
	// Redis stash rather than a column, so it is capped here.
	maxStateLength = 512
)

// Authorize validates an authorization request and stashes it for the consent page.
//
// Nothing is issued here and the caller is not authenticated: this leg only proves
// the request is well formed and comes from a registered client with a registered
// redirect_uri. The user's identity arrives on the second leg (Consent), the only
// place a code can be minted.
//
// Error redirectability is decided in a strict order. client_id and redirect_uri
// are validated first and every failure up to that point is non-redirectable — RFC
// 6749 §4.1.2.1 forbids bouncing the browser to an unverified URI, which would make
// this endpoint an open redirector. Once both check out, later failures carry
// Redirectable so the client learns why its request was refused.
func (s Service) Authorize(ctx context.Context, input AuthorizeInput) (*AuthorizeResult, error) {
	if err := s.checkAuthorizeLimit(ctx, input.ClientIP); err != nil {
		return nil, err
	}

	clientID := strings.TrimSpace(input.ClientID)
	if clientID == "" {
		return nil, newError(ErrInvalidRequest, "client_id 不能为空", nil)
	}
	client, err := s.Clients.FindActiveByClientID(ctx, clientID)
	if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInvalidArgument) {
		// A disabled client and an unknown one answer identically: distinguishing
		// them would confirm which client IDs exist.
		return nil, newError(ErrInvalidClient, "client_id 无效或客户端已停用", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询 OAuth 客户端失败", err)
	}

	redirectURI := strings.TrimSpace(input.RedirectURI)
	if redirectURI == "" {
		return nil, newError(ErrInvalidRequest, "redirect_uri 不能为空", nil)
	}
	// Exact string match against the registered set (PRD §4.10); a prefix rule would
	// let an attacker append a path the client never registered and receive the code.
	if !slices.Contains([]string(client.RedirectURIs), redirectURI) {
		return nil, newError(ErrInvalidRequest, "redirect_uri 与客户端注册值不匹配", nil)
	}

	// Past this point the client and its redirect_uri are verified, so errors may
	// travel back to the client.
	if !slices.Contains([]string(client.GrantTypes), grantTypeAuthorizationCode) {
		return nil, redirectableError(ErrUnauthorizedClient, "客户端未获授权使用 authorization_code", nil)
	}
	if strings.TrimSpace(input.ResponseType) != responseTypeCode {
		return nil, redirectableError(ErrUnsupportedResponse, "response_type 必须为 code", nil)
	}
	// Presence is checked on the trimmed value but the original is stashed and echoed
	// back: RFC 6749 §4.1.2 requires state to be returned exactly as received, since
	// the client compares it byte for byte as its CSRF token.
	if strings.TrimSpace(input.State) == "" {
		return nil, redirectableError(ErrInvalidRequest, "state 不能为空", nil)
	}
	if len(input.State) > maxStateLength {
		return nil, redirectableError(ErrInvalidRequest, "state 长度超出限制", nil)
	}
	state := input.State
	if strings.TrimSpace(input.CodeChallengeMethod) != pkceMethodS256 {
		return nil, redirectableError(ErrInvalidRequest, "code_challenge_method 必须为 S256", nil)
	}
	challenge := strings.TrimSpace(input.CodeChallenge)
	if challenge == "" {
		return nil, redirectableError(ErrInvalidRequest, "code_challenge 不能为空", nil)
	}
	// An S256 challenge is a fixed-width base64url digest; any other shape is refused
	// here so no code is minted from a value no verifier could ever match.
	if !auth.IsValidPKCEChallenge(challenge) {
		return nil, redirectableError(ErrInvalidRequest, "code_challenge 必须为 43 位 base64url S256 摘要", nil)
	}
	nonce := strings.TrimSpace(input.Nonce)
	if len(nonce) > maxAuthorizeParameterLength {
		return nil, redirectableError(ErrInvalidRequest, "nonce 长度超出限制", nil)
	}

	requested, err := parseRequestedScopes(input.Scope)
	if err != nil {
		return nil, redirectableError(ErrInvalidScope, "scope 无效：必须包含 openid，且仅支持受支持的取值", err)
	}
	if scopeErr := authorizeScopeForClient(client, requested); scopeErr != nil {
		return nil, scopeErr
	}

	requestID, err := newAuthorizeRequestID()
	if err != nil {
		return nil, newError(ErrInternal, "生成授权请求标识失败", err)
	}
	payload := AuthorizeRequestPayload{
		ClientID:            client.ClientID,
		ClientName:          client.ClientName,
		RedirectURI:         redirectURI,
		Scopes:              requested,
		State:               state,
		CodeChallenge:       challenge,
		CodeChallengeMethod: pkceMethodS256,
		Nonce:               nonce,
	}
	ttl := s.requestTTL()
	if err := s.Requests.SaveAuthorizeRequest(ctx, requestID, payload, ttl); err != nil {
		// Fail-closed: Redis holds the only copy of this request, so a write we
		// cannot confirm must not be reported as a pending authorization.
		return nil, newError(ErrDependencyUnavailable, "暂存授权请求失败，请重试", err)
	}

	return &AuthorizeResult{
		RequestID:  requestID,
		ExpiresIn:  int(ttl.Seconds()),
		ClientName: client.ClientName,
		Scopes:     requested,
	}, nil
}

// Consent turns an approved authorization request into an authorization code.
//
// The stash is consumed atomically before anything is issued, so one authorize
// request yields at most one code even if the consent page is submitted twice.
// Every code parameter comes from the stash rather than the request body, so a
// caller cannot approve one request and mint a code for a different client or
// scope.
func (s Service) Consent(ctx context.Context, input ConsentInput) (*ConsentResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	requestID := strings.TrimSpace(input.RequestID)
	if requestID == "" {
		return nil, newError(ErrInvalidRequest, "request_id 不能为空", nil)
	}

	// Only the approving path mints a code, so only it is rate-limited; a deny
	// consumes no budget, and a refused approve happens before the stash is spent
	// so the user can retry without re-starting the authorization.
	if input.Approve {
		if err := s.checkConsentLimit(ctx, input.UserID); err != nil {
			return nil, err
		}
	}

	payload, found, err := s.Requests.ConsumeAuthorizeRequest(ctx, requestID)
	if err != nil {
		return nil, newError(ErrDependencyUnavailable, "读取授权请求失败，请重试", err)
	}
	if !found {
		return nil, newError(ErrInvalidRequest, "授权请求无效或已过期，请重新发起授权", nil)
	}

	if !input.Approve {
		// RFC 6749 §4.1.2.1 reports a refusal to the client as access_denied. Like the
		// approval branch below the redirect_uri is re-checked against the live
		// registration, so nothing is delivered to a callback an operator removed.
		client, lookupErr := s.Clients.FindActiveByClientID(ctx, payload.ClientID)
		if errors.Is(lookupErr, repository.ErrNotFound) || errors.Is(lookupErr, repository.ErrInvalidArgument) {
			s.auditAuthorize(ctx, input, payload, nil, false, errcode.CodeUnauthenticated, "denied_client_gone")
			return nil, newError(ErrInvalidClient, "客户端已停用，请重新发起授权", nil)
		}
		if lookupErr != nil {
			s.auditAuthorize(ctx, input, payload, nil, false, errcode.CodeInternal, "denied_redirect_unverifiable")
			return nil, newError(ErrInternal, "查询 OAuth 客户端失败", lookupErr)
		}
		if !slices.Contains([]string(client.RedirectURIs), payload.RedirectURI) {
			s.auditAuthorize(ctx, input, payload, nil, false, errcode.CodeBadRequest, "denied_redirect_removed")
			return nil, newError(ErrInvalidRequest, "redirect_uri 已不在客户端注册值中，请重新发起授权", nil)
		}
		s.auditAuthorize(ctx, input, payload, nil, false, errcode.CodeForbidden, "denied")
		return &ConsentResult{
			RedirectURI: errorRedirectURI(payload.RedirectURI, payload.State, ErrorAccessDenied, "用户拒绝授权"),
		}, nil
	}

	client, err := s.Clients.FindActiveByClientID(ctx, payload.ClientID)
	if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInvalidArgument) {
		// The client was disabled between the two legs. The stash is already spent,
		// so the user must restart rather than receive a code for a dead client.
		return nil, newError(ErrInvalidClient, "客户端已停用，请重新发起授权", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询 OAuth 客户端失败", err)
	}
	// The redirect_uri is re-matched against the live registration so a removed
	// callback stops receiving codes immediately rather than for the stash's TTL.
	if !slices.Contains([]string(client.RedirectURIs), payload.RedirectURI) {
		return nil, newError(ErrInvalidRequest, "redirect_uri 已不在客户端注册值中，请重新发起授权", nil)
	}
	// Scopes are re-checked against the live registration so revoking a client's
	// admin scope stops old stashes from minting administrative codes. Not
	// redirectable: the request was valid when made, so the user is told to restart
	// rather than the client receiving an error it cannot act on.
	if scopeErr := checkScopeForClient(client, payload.Scopes); scopeErr != nil {
		s.auditAuthorize(ctx, input, payload, nil, false, errcode.CodeForbidden, "scope_revoked")
		return nil, newError(ErrInvalidScope, "scope 已不在客户端注册范围内，请重新发起授权", scopeErr)
	}

	user, err := s.Users.FindAuthUserByID(ctx, input.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询授权用户失败", err)
	}
	if user.State == model.UserStateDeleted {
		return nil, newError(ErrAccessDenied, "账号已注销", nil)
	}

	code, err := newAuthorizationCode()
	if err != nil {
		return nil, newError(ErrInternal, "生成授权码失败", err)
	}
	now := s.now()
	// The family starts here and is carried by the code into whatever token pair
	// redeems it, so a replayed code revokes the tokens already minted (PRD §4.10).
	familyID := uuid.NewString()
	nonce := payload.Nonce
	var noncePtr *string
	if nonce != "" {
		noncePtr = &nonce
	}
	redirectURI := payload.RedirectURI
	authorization := &model.OAuthAuthorization{
		Code:                code,
		ClientID:            client.ID,
		UserID:              user.ID,
		RedirectURI:         &redirectURI,
		Scopes:              model.StringArray(payload.Scopes),
		CodeChallenge:       payload.CodeChallenge,
		CodeChallengeMethod: payload.CodeChallengeMethod,
		Nonce:               noncePtr,
		FamilyID:            &familyID,
		ExpiresAt:           now.Add(s.codeTTL()),
		CreatedAt:           now,
	}
	if err := s.Authorizations.CreateWithGrant(ctx, authorization); err != nil {
		return nil, newError(ErrInternal, "创建授权码失败", err)
	}

	s.auditAuthorize(ctx, input, payload, &user.ID, true, 0, "granted")
	return &ConsentResult{
		RedirectURI: successRedirectURI(payload.RedirectURI, payload.State, code),
	}, nil
}

// ConsentInfo returns the verified client metadata for a pending authorization
// request. It peeks the stash rather than consuming it, so merely viewing the
// consent page does not spend the request. The client name and scopes come from
// the stash written by Authorize, never from the consent URL, so a crafted link
// cannot spoof which application is asking.
func (s Service) ConsentInfo(ctx context.Context, input ConsentInfoInput) (*ConsentInfoResult, error) {
	if err := s.checkConsentInfoLimit(ctx, input.UserID); err != nil {
		return nil, err
	}
	requestID := strings.TrimSpace(input.RequestID)
	if requestID == "" {
		return nil, newError(ErrInvalidRequest, "request_id 不能为空", nil)
	}
	payload, ttl, found, err := s.Requests.PeekAuthorizeRequest(ctx, requestID)
	if err != nil {
		return nil, newError(ErrDependencyUnavailable, "读取授权请求失败，请重试", err)
	}
	if !found {
		return nil, newError(ErrInvalidRequest, "授权请求无效或已过期，请重新发起授权", nil)
	}
	// The registration can change after the first leg, so the client is re-read and
	// the scope set re-checked against it, exactly as Consent does on submission;
	// otherwise a mid-flight revocation keeps the revoked scope on screen until the
	// stash expires.
	client, err := s.Clients.FindActiveByClientID(ctx, payload.ClientID)
	if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInvalidArgument) {
		return nil, newError(ErrInvalidClient, "客户端已停用，请重新发起授权", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询 OAuth 客户端失败", err)
	}
	if scopeErr := checkScopeForClient(client, payload.Scopes); scopeErr != nil {
		return nil, newError(ErrInvalidScope, "scope 已不在客户端注册范围内，请重新发起授权", scopeErr)
	}
	return &ConsentInfoResult{
		ClientName: payload.ClientName,
		Scopes:     payload.Scopes,
		ExpiresIn:  int(ttl.Seconds()),
	}, nil
}

// parseRequestedScopes parses the space-delimited wire scope parameter.
//
// Validation goes through internal/scope so the authorize endpoint and the signed
// JWT claim agree on which scope sets exist. It uses scope.Normalize over
// strings.Fields rather than scope.ParseClaim, since the wire parameter follows
// HTTP whitespace convention and may carry runs of spaces.
func parseRequestedScopes(raw string) ([]string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, scope.ErrInvalid
	}
	return scope.Normalize(strings.Fields(value))
}

// authorizeScopeForClient enforces PRD §4.10's per-client scope rule: every client,
// first-party included, may only request what its registration grants. The returned
// error is redirectable, since it is reached only after the client and redirect_uri
// are verified.
//
// The admin scopes carry an additional restriction on top of that, checked first:
// they may only be granted to a third-party client. See checkScopeForClient.
func authorizeScopeForClient(client *model.OAuthClient, requested []string) error {
	if err := checkScopeForClient(client, requested); err != nil {
		err.Redirectable = true
		return err
	}
	return nil
}

// checkScopeForClient is the predicate itself, returning a non-redirectable error.
//
// Split out from authorizeScopeForClient because the rule is re-applied on the
// consent and code-redemption legs, where the answer goes to the caller directly.
// A registration's scopes can change between legs, so this check is what makes a
// revoked grant take effect on codes already in flight.
//
// Admin scopes are refused for a public (first_party) client however the
// registration reads: a public client authenticates by PKCE alone, leaving an
// intercepted code one barrier short of the /admin surface. The user scopes carry
// no type constraint, since every /user endpoint operates on the token subject's
// own record. Not redundant now that ContainsAll pins every client type.
func checkScopeForClient(client *model.OAuthClient, requested []string) *Error {
	if scope.ContainsAdmin(requested) && client.ClientType != model.ClientTypeThirdParty {
		return newError(ErrInvalidScope, "admin scope 不可授予公开（first_party）客户端", nil)
	}
	granted, err := scope.ContainsAll([]string(client.Scopes), requested)
	if err != nil {
		return newError(ErrInvalidScope, "客户端注册的 scope 无效", err)
	}
	if !granted {
		return newError(ErrInvalidScope, "请求的 scope 超出客户端注册范围", nil)
	}
	return nil
}

// successRedirectURI appends code and state to the client's redirect_uri.
//
// Query parameters are merged into any already registered rather than replaced,
// and state is echoed verbatim so the client's byte-for-byte CSRF check holds.
func successRedirectURI(redirectURI, state, code string) string {
	return appendQuery(redirectURI, map[string]string{"code": code, "state": state})
}

// errorRedirectURI builds an RFC 6749 §4.1.2.1 error redirect.
func errorRedirectURI(redirectURI, state, code, description string) string {
	return appendQuery(redirectURI, map[string]string{
		"error":             code,
		"error_description": description,
		"state":             state,
	})
}

func appendQuery(rawURI string, parameters map[string]string) string {
	parsed, err := url.Parse(rawURI)
	if err != nil {
		// Unreachable for a registered URI, which was parsed at registration; return
		// the input unchanged to keep this total.
		return rawURI
	}
	query := parsed.Query()
	for key, value := range parameters {
		if value == "" {
			continue
		}
		query.Set(key, value)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (s Service) auditAuthorize(
	ctx context.Context,
	input ConsentInput,
	payload AuthorizeRequestPayload,
	userID *int64,
	success bool,
	errCode int,
	decision string,
) {
	subject := userID
	if subject == nil && input.UserID > 0 {
		// A refusal still identifies who refused; the account exists even though no
		// code was issued for it.
		id := input.UserID
		subject = &id
	}
	resourceID := payload.ClientID
	s.audit(ctx, subject, "oauth_authorize", &resourceID, success, errCode, input.ClientIP, input.UserAgent, map[string]any{
		"client_id": payload.ClientID,
		"scopes":    payload.Scopes,
		"decision":  decision,
	})
}

// userIDString renders a user ID as an OIDC subject.
func userIDString(userID int64) string {
	return strconv.FormatInt(userID, 10)
}
