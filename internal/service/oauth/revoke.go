package oauth

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

const tokenTypeHintAccess = "access_token"

// Revoke implements RFC 7009 token revocation over a whole token family.
//
// RFC 7009 §2.2 requires success for an unknown, expired or already-revoked
// token: the client's goal is that the token no longer works, which is already
// true, and answering otherwise would turn this endpoint into an oracle for
// which token values exist. Only client authentication and a malformed request
// produce errors.
//
// Revocation is family-wide by design (PRD §4.10). A client asking to revoke one
// token of a family is ending that session, and leaving the sibling access token
// live for up to its full TTL would contradict that.
func (s Service) Revoke(ctx context.Context, input RevokeInput) error {
	// Shares the token endpoint's limiter: this endpoint also authenticates a client
	// and resolves a presented token, so it offers the same guessing surface.
	if err := s.checkTokenLimit(ctx, input.ClientIP); err != nil {
		return err
	}
	client, err := s.authenticateClient(ctx, input.ClientID, input.ClientSecret)
	if err != nil {
		// Audited like the token endpoint's client-authentication failures: a
		// credential sweep against /oauth/revoke must leave a trail too.
		s.auditRevoke(ctx, nil, input.ClientID, input, false, errcode.CodeUnauthenticated, "client_auth_failed")
		return err
	}
	token := strings.TrimSpace(input.Token)
	if token == "" {
		return newError(ErrInvalidRequest, "token 不能为空", nil)
	}

	familyID, userID, found, err := s.resolveTokenFamily(ctx, token, input.TokenTypeHint, client.ID)
	if err != nil {
		return err
	}
	if !found {
		// Deliberately a success. See the doc comment.
		s.auditRevoke(ctx, nil, client.ClientID, input, true, 0, "not_found")
		return nil
	}

	// Unlike the replay defenses, this caller reports the outcome to the requester.
	// RFC 7009's success contract is that the token no longer works; answering 200
	// for a revocation that did not commit tells the client the session is gone when
	// it is live for its full TTL, and the client has no reason to retry.
	if revokeErr := s.revokeFamilyErr(ctx, familyID); revokeErr != nil {
		slog.ErrorContext(ctx, "revoke oauth token family",
			"security_event", "token_family_revocation_failed",
			"family_id", familyID, "error", revokeErr)
		s.auditRevoke(ctx, userID, client.ClientID, input, false, errcode.CodeInternal, "revocation_failed")
		return newError(ErrInternal, "撤销 Token 失败，请重试", revokeErr)
	}
	s.auditRevoke(ctx, userID, client.ClientID, input, true, 0, "revoked")
	return nil
}

// resolveTokenFamily finds the family a presented token belongs to.
//
// token_type_hint only reorders the lookups, per RFC 7009 §2.1: a client that
// guesses wrong must still have its token revoked, so a miss on the hinted type
// falls through to the other. The client ownership check is what stops one client
// revoking another's sessions; a token owned by a different client reads as not
// found, which is also the answer RFC 7009 wants for a token this client cannot
// act on.
func (s Service) resolveTokenFamily(
	ctx context.Context,
	token, hint string,
	clientID int64,
) (familyID string, userID *int64, found bool, err error) {
	lookups := []func() (string, *int64, bool, error){
		func() (string, *int64, bool, error) { return s.familyByRefreshToken(ctx, token, clientID) },
		func() (string, *int64, bool, error) { return s.familyByAccessJTI(ctx, token, clientID) },
	}
	if strings.TrimSpace(hint) == tokenTypeHintAccess {
		lookups[0], lookups[1] = lookups[1], lookups[0]
	}
	for _, lookup := range lookups {
		familyID, userID, found, err = lookup()
		if err != nil || found {
			return familyID, userID, found, err
		}
	}
	return "", nil, false, nil
}

func (s Service) familyByRefreshToken(ctx context.Context, token string, clientID int64) (string, *int64, bool, error) {
	tokenHash, err := s.RefreshTokens.HashRefreshToken(token)
	if err != nil {
		// Not shaped like one of our refresh tokens; let the caller try the other form.
		return "", nil, false, nil
	}
	refresh, err := s.Tokens.FindRefreshToken(ctx, tokenHash)
	if errors.Is(err, repository.ErrNotFound) {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, newError(ErrInternal, "查询 refresh_token 失败", err)
	}
	if refresh.ClientID != clientID {
		return "", nil, false, nil
	}
	return refresh.FamilyID, &refresh.UserID, true, nil
}

// familyByAccessJTI resolves an access token by verifying it and looking up its
// JTI. The signature is verified rather than the JWT merely decoded: an
// unverified token's claims are attacker-controlled, and trusting its jti would
// let anyone revoke an arbitrary family by forging one.
//
// An expired token is still resolved, because revocation here is family-wide: the
// presented access token being useless does not make its family useless, and its
// sibling refresh token can stay live for weeks. Treating expiry as not-found made
// the endpoint answer 200 while revoking nothing — and an expired access token is
// the ordinary state of a client that has been idle and now wants to log out.
// VerifyExpiredAccessToken forgives only the expiry; issuer, audience, kid and
// signature are still enforced, and ownership is decided below against the database
// row rather than anything the token asserts.
func (s Service) familyByAccessJTI(ctx context.Context, token string, clientID int64) (string, *int64, bool, error) {
	// VerifyExpiredAccessToken is the one call that accepts both a live token and
	// an expired one (forgiving only the clock; signature, issuer, audience and
	// kid stay enforced), so an expired token does not pay for two full EdDSA
	// verifies.
	claims, err := s.JWT.VerifyExpiredAccessToken(token)
	if err != nil {
		return "", nil, false, nil
	}
	access, err := s.Tokens.FindAccessTokenByJTI(ctx, claims.ID)
	if errors.Is(err, repository.ErrNotFound) {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, newError(ErrInternal, "查询 access token 失败", err)
	}
	if access.ClientID != clientID || access.FamilyID == nil {
		return "", nil, false, nil
	}
	return *access.FamilyID, &access.UserID, true, nil
}

func (s Service) auditRevoke(
	ctx context.Context,
	userID *int64,
	clientID string,
	input RevokeInput,
	success bool,
	errCode int,
	outcome string,
) {
	resourceID := clientID
	s.audit(ctx, userID, "oauth_revoke", &resourceID, success, errCode, input.ClientIP, input.UserAgent, map[string]any{
		"client_id":       clientID,
		"token_type_hint": strings.TrimSpace(input.TokenTypeHint),
		"outcome":         outcome,
	})
}
