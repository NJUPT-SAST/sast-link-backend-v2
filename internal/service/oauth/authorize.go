package oauth

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"

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
)

// Authorize validates an authorization request and stashes it for the consent page.
//
// Nothing is issued here and the caller is not authenticated: this leg only
// proves the request is well formed and comes from a registered client with a
// registered redirect_uri. The user's identity arrives on the second leg
// (Consent), which is the only place a code can be minted.
//
// Error redirectability is decided in a strict order. client_id and redirect_uri
// are validated first and every failure up to that point is non-redirectable —
// RFC 6749 §4.1.2.1 forbids bouncing the browser to an unverified URI, which
// would make this endpoint an open redirector. Once both check out, later
// failures carry Redirectable so the client learns why its request was refused.
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
	// Exact string match against the registered set, per PRD §4.10. No prefix or
	// host comparison: a prefix rule lets an attacker append a path the client
	// never registered and receive the code there.
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
	// Presence is checked on the trimmed value so whitespace alone is not a state,
	// but the original is what gets stashed and echoed back. RFC 6749 §4.1.2 requires
	// state to be returned exactly as received: it is the client's CSRF token and the
	// client compares it byte for byte, so trimming it would break that comparison
	// for any client whose state carries surrounding whitespace.
	if strings.TrimSpace(input.State) == "" {
		return nil, redirectableError(ErrInvalidRequest, "state 不能为空", nil)
	}
	state := input.State
	if strings.TrimSpace(input.CodeChallengeMethod) != pkceMethodS256 {
		return nil, redirectableError(ErrInvalidRequest, "code_challenge_method 必须为 S256", nil)
	}
	challenge := strings.TrimSpace(input.CodeChallenge)
	if challenge == "" {
		return nil, redirectableError(ErrInvalidRequest, "code_challenge 不能为空", nil)
	}

	requested, err := parseRequestedScopes(input.Scope)
	if err != nil {
		return nil, redirectableError(ErrInvalidScope, "scope 无效：必须包含 openid，且仅支持 openid/profile/email", err)
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
		RedirectURI:         redirectURI,
		Scopes:              requested,
		State:               state,
		CodeChallenge:       challenge,
		CodeChallengeMethod: pkceMethodS256,
		Nonce:               strings.TrimSpace(input.Nonce),
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
// Every code parameter comes from the stash rather than the request body: the
// body is authenticated but its echoed parameters are not trusted, or a caller
// could approve one request and mint a code for a different client or scope.
func (s Service) Consent(ctx context.Context, input ConsentInput) (*ConsentResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	requestID := strings.TrimSpace(input.RequestID)
	if requestID == "" {
		return nil, newError(ErrInvalidRequest, "request_id 不能为空", nil)
	}

	payload, found, err := s.Requests.ConsumeAuthorizeRequest(ctx, requestID)
	if err != nil {
		return nil, newError(ErrDependencyUnavailable, "读取授权请求失败，请重试", err)
	}
	if !found {
		return nil, newError(ErrInvalidRequest, "授权请求无效或已过期，请重新发起授权", nil)
	}

	if !input.Approve {
		// RFC 6749 §4.1.2.1: a refusal is reported to the client as access_denied,
		// not hidden. The redirect_uri was validated on the first leg, so echoing it
		// back is safe.
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

	user, err := s.Users.FindByID(ctx, input.UserID)
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
	// The family starts here, at consent, and is carried by the code into whatever
	// token pair redeems it. That is what lets a replayed code revoke the tokens
	// already minted from it (PRD §4.10).
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
	if err := s.Authorizations.Create(ctx, authorization); err != nil {
		return nil, newError(ErrInternal, "创建授权码失败", err)
	}

	s.auditAuthorize(ctx, input, payload, &user.ID, true, 0, "granted")
	return &ConsentResult{
		RedirectURI: successRedirectURI(payload.RedirectURI, payload.State, code),
	}, nil
}

// parseRequestedScopes parses the space-delimited wire scope parameter.
//
// Uses scope.ParseClaim rather than a hand split so the authorize endpoint and
// the JWT claim agree on what a valid scope string is, including openid being
// mandatory for this service.
func parseRequestedScopes(raw string) ([]string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, scope.ErrInvalid
	}
	// The wire form allows runs of spaces where the claim form does not, so
	// collapse them before the strict parse.
	return scope.Normalize(strings.Fields(value))
}

// authorizeScopeForClient enforces PRD §4.10's per-client scope rule: a
// first-party client may request any supported scope, a third-party client only
// what it registered. The returned error is redirectable, since it is reached
// only after the client and redirect_uri are verified.
func authorizeScopeForClient(client *model.OAuthClient, requested []string) error {
	if client.ClientType == model.ClientTypeFirstParty {
		return nil
	}
	granted, err := scope.ContainsAll([]string(client.Scopes), requested)
	if err != nil {
		return redirectableError(ErrInvalidScope, "客户端注册的 scope 无效", err)
	}
	if !granted {
		return redirectableError(ErrInvalidScope, "请求的 scope 超出客户端注册范围", nil)
	}
	return nil
}

// successRedirectURI appends code and state to the client's redirect_uri.
//
// Query parameters are merged into any the client already registered rather than
// replacing them, and state is echoed verbatim: the client compares it against
// what it sent to detect CSRF, so any normalization here would break that check.
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
		// Unreachable for a registered URI, which was parsed when the client was
		// created. Returning the input unchanged keeps this total rather than
		// panicking on a value the caller cannot influence.
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
