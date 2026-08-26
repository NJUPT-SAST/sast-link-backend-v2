package adminclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

// newClientID generates a public client identifier server-side; accepting one from
// the request would let a caller register under the built-in first-party client's
// id, which the internal API's azp gate pins to.
func newClientID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate client ID: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// ListClients returns every registration, disabled ones included.
func (s Service) ListClients(ctx context.Context) ([]Client, error) {
	if s.Clients == nil {
		return nil, newError(ErrInternal, "客户端仓储未配置", nil)
	}
	stored, err := s.Clients.List(ctx)
	if err != nil {
		return nil, newError(ErrInternal, "查询 OAuth 客户端失败", err)
	}
	clients := make([]Client, 0, len(stored))
	for i := range stored {
		clients = append(clients, toClient(&stored[i]))
	}
	return clients, nil
}

// CreateClient registers a new OAuth client. A third_party client gets a generated
// secret returned exactly once, only its hash persisted; a first_party client is
// public with no secret. PKCE is required of both — the secret is an additional
// client-authentication factor, not an alternative to it.
func (s Service) CreateClient(ctx context.Context, input CreateClientInput) (*CreateClientResult, error) {
	if s.Clients == nil {
		return nil, newError(ErrInternal, "客户端仓储未配置", nil)
	}
	client, secret, err := s.buildClient(input)
	if err != nil {
		s.auditCreate(ctx, input, nil, false, errorCode(err), 0)
		return nil, err
	}
	if err := s.Clients.Create(ctx, client); err != nil {
		// client_id is random, so a unique violation here is a genuine fault to retry,
		// not a caller-visible conflict.
		s.auditCreate(ctx, input, &client.ClientID, false, ErrInternal.Code, 0)
		return nil, newError(ErrInternal, "创建 OAuth 客户端失败", err)
	}
	s.auditCreate(ctx, input, &client.ClientID, true, 0, 0)
	return &CreateClientResult{Client: toClient(client), ClientSecret: secret}, nil
}

// buildClient validates the input and assembles the row to insert.
func (s Service) buildClient(input CreateClientInput) (*model.OAuthClient, string, error) {
	name, err := validateClientName(input.ClientName)
	if err != nil {
		return nil, "", err
	}
	clientType, err := validateClientType(input.ClientType)
	if err != nil {
		return nil, "", err
	}
	redirectURIs, err := validateRedirectURIs(input.RedirectURIs)
	if err != nil {
		return nil, "", err
	}
	grantTypes, err := validateGrantTypes(input.GrantTypes)
	if err != nil {
		return nil, "", err
	}
	// Normalized through the same gate /oauth/authorize uses, so a registration cannot
	// hold a scope set the authorize endpoint would reject.
	scopes, err := scope.Normalize(input.Scopes)
	if err != nil {
		return nil, "", newError(ErrInvalidInput, "scopes 非法，必须包含 openid 且仅含受支持的值", err)
	}
	// Granting a capability scope at registration is allowed only under the same
	// conditions an update must satisfy; the capability rules live here, not in
	// scope.Normalize.
	if grantErr := s.checkCapabilityScopeGrant(capabilityScopeGrant{
		scopes:              scopes,
		clientType:          clientType,
		actorClientID:       input.ActorClientID,
		redirectURIsChanged: false,
	}); grantErr != nil {
		return nil, "", grantErr
	}
	clientID, err := s.newClientID()
	if err != nil {
		return nil, "", newError(ErrInternal, "生成 client_id 失败", err)
	}
	active := true
	client := &model.OAuthClient{
		ClientID:     clientID,
		ClientName:   name,
		ClientType:   clientType,
		RedirectURIs: redirectURIs,
		GrantTypes:   grantTypes,
		Scopes:       model.StringArray(scopes),
		IsActive:     &active,
	}
	if clientType != model.ClientTypeThirdParty {
		return client, "", nil
	}
	secret, hash, err := s.Secrets.NewClientSecret()
	if err != nil {
		return nil, "", newError(ErrInternal, "生成 client_secret 失败", err)
	}
	client.ClientSecretHash = &hash
	return client, secret, nil
}

// capabilityScopeGrant is the merged state a capability-scope guard decides on: what
// the registration would look like after this request, not what the request happens
// to mention. A struct keeps the guard reusable across create and update.
type capabilityScopeGrant struct {
	// scopes is post-merge: for an update, the submitted value when present and
	// the stored one otherwise.
	scopes []string
	// clientType is the stored type on update; client_type can only come from the
	// row, since UpdateClientInput does not carry it.
	clientType    model.ClientType
	actorClientID string
	// redirectURIsChanged reports whether this same request also rewrites the
	// callback list.
	redirectURIsChanged bool
}

// checkCapabilityScopeGrant is the gate on the capability scopes: it decides
// whether a registration may end up holding an admin scope or a user scope.
//
// Every check keys on the merged post-request state, so a guard cannot be bypassed
// by splitting a change across two requests. The admin scopes are confined to
// third_party clients: a public (first_party) client authenticates its token
// request by PKCE alone, so an intercepted authorization code would be one barrier
// short of an /admin credential, where a confidential client has two (client_secret
// + PKCE). The user scopes carry no type constraint — every /user endpoint operates
// on the token subject's own record, so they are never a look-up-anyone credential.
// The refresh grant is permitted: the /admin role gate reads the subject's role from
// the database on every request, so refreshing an admin-scoped token never widens
// who may use it. Applied on both doors, create and update.
func (s Service) checkCapabilityScopeGrant(grant capabilityScopeGrant) error {
	hasAdmin := scope.ContainsAdmin(grant.scopes)
	hasUser := scope.ContainsUser(grant.scopes)
	if !hasAdmin && !hasUser {
		return nil
	}
	if hasAdmin && grant.clientType != model.ClientTypeThirdParty {
		return newError(ErrInvalidInput, "admin scope 仅可授予 third_party 客户端", nil)
	}
	// Only the console may create capability; otherwise a scoped client holding
	// admin:write could grow the set of delegates without operator approval.
	if !s.actorIsConsole(grant.actorClientID) {
		return newError(ErrProtectedClient, "capability scope 只能由控制台授予", nil)
	}
	// Granting the capability and repointing the callbacks must land in separate
	// requests, so each audit row names one change.
	if grant.redirectURIsChanged {
		return newError(ErrInvalidInput, "授予 capability scope 与修改 redirect_uris 不可在同一请求中完成", nil)
	}
	return nil
}

// UpdateClient applies a partial update to a registration. Disabling a client,
// narrowing its scopes, or newly granting it a capability scope revokes its live
// tokens atomically with the change, so access stops now rather than at token
// expiry.
func (s Service) UpdateClient(ctx context.Context, input UpdateClientInput) (*UpdateClientResult, error) {
	if s.Clients == nil {
		return nil, newError(ErrInternal, "客户端仓储未配置", nil)
	}
	if input.ClientPK <= 0 {
		return nil, newError(ErrNotFound, "OAuth 客户端不存在", nil)
	}
	fields, err := s.updateFields(input)
	if err != nil {
		s.auditUpdate(ctx, input, false, errorCode(err), 0, nil, nil)
		return nil, err
	}
	current, err := s.Clients.FindByID(ctx, input.ClientPK)
	if errors.Is(err, repository.ErrNotFound) {
		// Audited like every other rejection on this path.
		s.auditUpdate(ctx, input, false, ErrNotFound.Code, 0, nil, nil)
		return nil, newError(ErrNotFound, "OAuth 客户端不存在", nil)
	}
	if err != nil {
		s.auditUpdate(ctx, input, false, ErrInternal.Code, 0, nil, nil)
		return nil, newError(ErrInternal, "查询 OAuth 客户端失败", err)
	}
	// Checked after the row is loaded: the guard keys on the stored client_id, not
	// the caller-supplied primary key.
	if protectedErr := s.checkProtected(current, input); protectedErr != nil {
		s.auditUpdate(ctx, input, false, errorCode(protectedErr), 0, &current.ClientID, nil)
		return nil, protectedErr
	}
	// After checkProtected, so a protected-target refusal names that reason rather
	// than a scope rule the operator cannot act on. Both key on the stored row.
	nextScopes, mergeErr := mergedRegistration(current, input)
	if mergeErr != nil {
		s.auditUpdate(ctx, input, false, errorCode(mergeErr), 0, &current.ClientID, nil)
		return nil, mergeErr
	}
	if grantErr := s.checkCapabilityScopeGrant(capabilityScopeGrant{
		scopes:              nextScopes,
		clientType:          current.ClientType,
		actorClientID:       input.ActorClientID,
		redirectURIsChanged: input.RedirectURIs != nil,
	}); grantErr != nil {
		s.auditUpdate(ctx, input, false, errorCode(grantErr), 0, &current.ClientID, nil)
		return nil, grantErr
	}
	reason := revocationReason(current, nextScopes)
	revoke := (input.IsActive != nil && !*input.IsActive && current.IsActive != nil && *current.IsActive) ||
		reason.scopesNarrowed() || reason.AdminScopeGranted || reason.UserScopeGranted
	now := s.now()
	entries, revokedRefresh, err := s.Clients.UpdateAndRevoke(ctx, input.ClientPK, fields, revoke, now)
	if errors.Is(err, repository.ErrNotFound) {
		// Audited: a row that vanished between the read and the write is how an
		// incident review finds the concurrent delete that raced this update.
		s.auditUpdate(ctx, input, false, ErrNotFound.Code, 0, &current.ClientID, nil)
		return nil, newError(ErrNotFound, "OAuth 客户端不存在", nil)
	}
	if err != nil {
		// The update never persisted, so the audit records it without the computed
		// capability change, which would read as a revocation that did not happen.
		s.auditUpdate(ctx, input, false, ErrInternal.Code, 0, &current.ClientID, nil)
		return nil, newError(ErrInternal, "更新 OAuth 客户端失败", err)
	}
	// Both sides of the revocation are reported: live access tokens plus the revoked
	// refresh families.
	total := len(entries) + int(revokedRefresh)
	s.deliverBlacklist(ctx, entries, now)
	s.auditUpdate(ctx, input, true, 0, total, &current.ClientID, &reason)
	return &UpdateClientResult{RevokedTokens: total}, nil
}

// DeleteClient permanently removes a registration. Through ON DELETE CASCADE the
// row, its authorization codes and token metadata are gone, so every token it
// issued is cut immediately; the still-live JTIs are enqueued for blacklist
// delivery so the auth-state cache is invalidated along with the rows. Any
// administrator, console or delegated, may deregister any non-built-in client —
// unlike granting a capability, deleting removes the credential and the scope it
// carried, so no console gate is needed.
func (s Service) DeleteClient(ctx context.Context, input DeleteClientInput) (*DeleteClientResult, error) {
	if s.Clients == nil {
		return nil, newError(ErrInternal, "客户端仓储未配置", nil)
	}
	if input.ClientPK <= 0 {
		// Audited like every other rejection on this path; a direct service caller
		// can reach this check.
		s.auditDelete(ctx, input, nil, false, ErrNotFound.Code, 0)
		return nil, newError(ErrNotFound, "OAuth 客户端不存在", nil)
	}
	current, err := s.Clients.FindByID(ctx, input.ClientPK)
	if errors.Is(err, repository.ErrNotFound) {
		// Audited like every other rejection on this path.
		s.auditDelete(ctx, input, nil, false, ErrNotFound.Code, 0)
		return nil, newError(ErrNotFound, "OAuth 客户端不存在", nil)
	}
	if err != nil {
		s.auditDelete(ctx, input, nil, false, ErrInternal.Code, 0)
		return nil, newError(ErrInternal, "查询 OAuth 客户端失败", err)
	}
	// The built-in client is a self-destruct guard, not a permission narrowing:
	// deleting it locks everyone out of login/refresh/registration with no console
	// path back, so the refusal applies to the console itself.
	if protected := strings.TrimSpace(s.ProtectedClientID); protected != "" && current.ClientID == protected {
		s.auditDelete(ctx, input, current, false, ErrProtectedClient.Code, 0)
		return nil, newError(ErrProtectedClient, "内置客户端不可删除", nil)
	}
	now := s.now()
	entries, revokedRefresh, err := s.Clients.DeleteAndRevoke(ctx, input.ClientPK, now)
	if errors.Is(err, repository.ErrNotFound) {
		// Audited like every other rejection: the row vanished between the read and
		// the delete.
		s.auditDelete(ctx, input, current, false, ErrNotFound.Code, 0)
		return nil, newError(ErrNotFound, "OAuth 客户端不存在", nil)
	}
	if err != nil {
		// The delete never committed, so the audit records a failed attempt, not a
		// deletion.
		s.auditDelete(ctx, input, current, false, ErrInternal.Code, 0)
		return nil, newError(ErrInternal, "删除 OAuth 客户端失败", err)
	}
	// Both sides of the revocation are reported: live access tokens plus the revoked
	// refresh families.
	total := len(entries) + int(revokedRefresh)
	s.deliverBlacklist(ctx, entries, now)
	s.auditDelete(ctx, input, current, true, 0, total)
	return &DeleteClientResult{RevokedTokens: total}, nil
}

// RotateClientSecret reissues a confidential client's secret — returned exactly
// once, only its hash stored — without disturbing existing tokens, so a leaked
// credential is cut without logging anyone out. Refused for a public (first_party)
// client, which has no secret, and for any non-console actor, so a delegated token
// cannot re-key the client it was issued to.
func (s Service) RotateClientSecret(ctx context.Context, input RotateClientSecretInput) (*RotateClientSecretResult, error) {
	if s.Clients == nil {
		return nil, newError(ErrInternal, "客户端仓储未配置", nil)
	}
	current, err := s.Clients.FindByID(ctx, input.ClientPK)
	if errors.Is(err, repository.ErrNotFound) {
		// Audited like every other rejection: a client_id probe after a leak looks
		// exactly like this, and ResourceID stays nil for an unresolved target.
		s.auditRotateSecret(ctx, input, nil, false, ErrNotFound.Code)
		return nil, newError(ErrNotFound, "OAuth 客户端不存在", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询 OAuth 客户端失败", err)
	}
	if current.ClientSecretHash == nil {
		s.auditRotateSecret(ctx, input, &current.ClientID, false, ErrInvalidInput.Code)
		return nil, newError(ErrInvalidInput, "该客户端是公开客户端，没有 client_secret 可轮换", nil)
	}
	// Only the console may rotate a capability client's secret, mirroring
	// checkProtected's console-actor rule for every other sensitive edit.
	if !s.actorIsConsole(input.ActorClientID) {
		s.auditRotateSecret(ctx, input, &current.ClientID, false, ErrProtectedClient.Code)
		return nil, newError(ErrProtectedClient, "client_secret 只能由控制台轮换", nil)
	}
	secret, hash, err := s.Secrets.NewClientSecret()
	if err != nil {
		s.auditRotateSecret(ctx, input, &current.ClientID, false, ErrInternal.Code)
		return nil, newError(ErrInternal, "生成 client_secret 失败", err)
	}
	now := s.now()
	if _, _, err := s.Clients.UpdateAndRevoke(ctx, input.ClientPK, map[string]any{"client_secret": hash}, false, now); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			s.auditRotateSecret(ctx, input, &current.ClientID, false, ErrNotFound.Code)
			return nil, newError(ErrNotFound, "OAuth 客户端不存在", nil)
		}
		s.auditRotateSecret(ctx, input, &current.ClientID, false, ErrInternal.Code)
		return nil, newError(ErrInternal, "更新 client_secret 失败", err)
	}
	s.auditRotateSecret(ctx, input, &current.ClientID, true, 0)
	return &RotateClientSecretResult{ClientSecret: secret}, nil
}

// mergedRegistration resolves the registration's post-merge scopes: the submitted
// value where present, the stored one otherwise. A normalization failure must abort
// the guard rather than fall back to the stored set, or the post-merge check would
// run on the wrong state.
func mergedRegistration(current *model.OAuthClient, input UpdateClientInput) ([]string, error) {
	scopes := []string(current.Scopes)
	if input.Scope != nil {
		normalized, err := scope.Normalize(*input.Scope)
		if err != nil {
			return nil, newError(ErrInvalidInput, "scopes 非法，必须包含 openid 且仅含受支持的值", err)
		}
		scopes = normalized
	}
	return scopes, nil
}

// revocation describes what an update does to a client's granted capability, which
// decides whether its live tokens must be cut.
type revocation struct {
	// ScopesRemoved are the scopes the registration held and no longer will.
	ScopesRemoved []string
	// AdminScopeGranted reports the registration gaining administrative capability;
	// it drives the revoke decision, not the audit trail.
	AdminScopeGranted bool
	// AdminScopesAdded names the admin scopes this update newly granted, for the
	// audit trail.
	AdminScopesAdded []string
	// UserScopeGranted reports the registration gaining self-service capability; it
	// drives the revoke decision.
	UserScopeGranted bool
	// UserScopesAdded names the user scopes this update newly granted, for the audit
	// trail.
	UserScopesAdded []string
}

func (r revocation) scopesNarrowed() bool {
	return len(r.ScopesRemoved) > 0
}

// revocationReason compares the stored scopes against the merged ones. A removed
// scope revokes — an access token carries the scope it was signed with, so a narrowed
// registration would otherwise leave credentials asserting a capability just taken
// away. An added ordinary scope does not revoke: existing tokens do not gain it.
// Newly granting a capability scope does revoke, cutting dormant refresh families so
// they cannot re-activate the new scope without a fresh authorization.
func revocationReason(current *model.OAuthClient, nextScopes []string) revocation {
	stored := []string(current.Scopes)
	removed := make([]string, 0, len(stored))
	for _, name := range stored {
		if !slices.Contains(nextScopes, name) {
			removed = append(removed, name)
		}
	}
	added := make([]string, 0, len(nextScopes))
	userAdded := make([]string, 0, len(nextScopes))
	for _, name := range nextScopes {
		if !slices.Contains(stored, name) {
			switch {
			case scope.IsAdmin(name):
				added = append(added, name)
			case scope.IsUser(name):
				userAdded = append(userAdded, name)
			}
		}
	}
	return revocation{
		ScopesRemoved:     removed,
		AdminScopeGranted: scope.ContainsAdmin(nextScopes) && !scope.ContainsAdmin(stored),
		AdminScopesAdded:  added,
		UserScopeGranted:  scope.ContainsUser(nextScopes) && !scope.ContainsUser(stored),
		UserScopesAdded:   userAdded,
	}
}

// updateFields validates the present fields and builds the column map.
func (s Service) updateFields(input UpdateClientInput) (map[string]any, error) {
	fields := make(map[string]any, 3)
	if input.ClientName != nil {
		name, err := validateClientName(*input.ClientName)
		if err != nil {
			return nil, err
		}
		fields["client_name"] = name
	}
	if input.RedirectURIs != nil {
		uris, err := validateRedirectURIs(*input.RedirectURIs)
		if err != nil {
			return nil, err
		}
		fields["redirect_uris"] = uris
	}
	if input.IsActive != nil {
		fields["is_active"] = *input.IsActive
	}
	if input.GrantTypes != nil {
		grants, err := validateGrantTypes(*input.GrantTypes)
		if err != nil {
			return nil, err
		}
		fields["grant_types"] = grants
	}
	if input.Scope != nil {
		scopes, err := scope.Normalize(*input.Scope)
		if err != nil {
			return nil, newError(ErrInvalidInput, "scopes 非法，必须包含 openid 且仅含受支持的值", err)
		}
		// Whether a capability scope may be included is decided later by
		// checkCapabilityScopeGrant, which keys on the stored row.
		fields["scopes"] = model.StringArray(scopes)
	}
	if len(fields) == 0 {
		return nil, newError(ErrInvalidInput, "没有可更新的字段", nil)
	}
	return fields, nil
}

func toClient(client *model.OAuthClient) Client {
	active := client.IsActive != nil && *client.IsActive
	return Client{
		ID:           client.ID,
		ClientID:     client.ClientID,
		ClientName:   client.ClientName,
		ClientType:   string(client.ClientType),
		RedirectURIs: []string(client.RedirectURIs),
		GrantTypes:   []string(client.GrantTypes),
		Scopes:       []string(client.Scopes),
		IsActive:     active,
		CreatedAt:    client.CreatedAt.UTC(),
		UpdatedAt:    client.UpdatedAt.UTC(),
	}
}

// errorCode extracts the business code from a typed error for the audit trail.
func errorCode(err error) int {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return ErrInternal.Code
}
