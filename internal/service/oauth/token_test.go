package oauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// issueCode drives the full authorize + consent flow and returns the code.
func issueCode(t *testing.T, h *harness, clientID string, scopeValue string) string {
	t.Helper()
	input := validAuthorizeInput(t)
	input.ClientID = clientID
	if scopeValue != "" {
		input.Scope = scopeValue
	}
	authorized, err := h.service.Authorize(context.Background(), input)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if _, err := h.service.Consent(context.Background(), ConsentInput{
		RequestID: authorized.RequestID,
		Approve:   true,
		UserID:    1,
	}); err != nil {
		t.Fatalf("Consent() error = %v", err)
	}
	if len(h.authorizations.created) == 0 {
		t.Fatal("no authorization code was created")
	}
	return h.authorizations.created[len(h.authorizations.created)-1].Code
}

func validCodeTokenInput(code string) TokenInput {
	return TokenInput{
		GrantType:    grantTypeAuthorizationCode,
		Code:         code,
		RedirectURI:  testRedirectURI,
		ClientID:     testPublicClientID,
		CodeVerifier: testVerifier,
		ClientIP:     "203.0.113.10",
	}
}

func TestTokenAuthorizationCodeIssuesPairAndIDToken(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid profile email")

	result, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if result.TokenType != BearerTokenType || result.ExpiresIn != 3600 {
		t.Fatalf("result = %+v, want Bearer with a 3600s access token", result)
	}
	if result.Scope != "openid profile email" {
		t.Fatalf("scope = %q, want the granted scopes", result.Scope)
	}
	if result.AccessToken == "" || result.RefreshToken == "" || result.IDToken == "" {
		t.Fatalf("result = %+v, want all three tokens", result)
	}

	// The access token must remain verifiable by this service's own middleware:
	// /userinfo authenticates with it.
	claims, err := h.service.JWT.VerifyAccessToken(result.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.Subject != "1" || claims.TokenVersion != 2 {
		t.Fatalf("access claims = %+v, want the user's subject and token_version", claims)
	}

	// The rows must be persisted under the code's family, or a later replay of that
	// code could not revoke these tokens.
	stored := h.authorizations.created[0]
	if h.tokens.createdAccess == nil || h.tokens.createdAccess.FamilyID == nil ||
		*h.tokens.createdAccess.FamilyID != *stored.FamilyID {
		t.Fatalf("persisted access family = %v, want the code's family %v",
			h.tokens.createdAccess, stored.FamilyID)
	}
	if h.tokens.createdRefresh.Sequence != 0 {
		t.Fatalf("initial refresh sequence = %d, want 0", h.tokens.createdRefresh.Sequence)
	}
	if actions := h.audit.actions(); len(actions) != 2 || actions[1] != "oauth_token" {
		t.Fatalf("audit actions = %v, want oauth_authorize then oauth_token", actions)
	}
}

// auth_time must be the moment the user consented, which is when the code row was
// created — not the moment the client got around to redeeming it.
func TestTokenIDTokenAuthTimeIsConsentInstant(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid")
	consentedAt := h.authorizations.created[0].CreatedAt

	result, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	claims := parseIDTokenClaims(t, h, result.IDToken)
	if claims.AuthTime != consentedAt.Unix() {
		t.Fatalf("auth_time = %d, want the consent instant %d", claims.AuthTime, consentedAt.Unix())
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != testPublicClientID {
		t.Fatalf("id_token aud = %v, want the client_id", claims.Audience)
	}
	if claims.Nonce != "n-0S6_WzA2Mj" {
		t.Fatalf("id_token nonce = %q, want the authorization request nonce", claims.Nonce)
	}
	// openid alone must not leak profile or email claims.
	if claims.Name != "" || claims.Email != "" {
		t.Fatalf("id_token = %+v, want no profile/email claims for scope openid", claims)
	}
}

// A replayed code means the code leaked; PRD §4.10 requires cutting the whole
// family, including the tokens already minted from the first redemption.
func TestTokenAuthorizationCodeReplayRevokesFamily(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid profile")
	familyID := *h.authorizations.created[0].FamilyID

	first, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("first Token() error = %v", err)
	}

	_, err = h.service.Token(context.Background(), validCodeTokenInput(code))
	requireOAuthError(t, err, ErrorInvalidGrant)

	if len(h.tokens.revokedFamilies) != 1 || h.tokens.revokedFamilies[0] != familyID {
		t.Fatalf("revoked families = %v, want the replayed code's family %q", h.tokens.revokedFamilies, familyID)
	}
	// The already-issued access token must now be revoked in the DB and queued for
	// the blacklist, or it would stay usable for the rest of its TTL.
	firstClaims, err := h.service.JWT.VerifyAccessToken(first.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	access := h.tokens.accessByJTI[firstClaims.ID]
	if access == nil || access.RevokedAt == nil {
		t.Fatalf("first access token = %+v, want revoked after the replay", access)
	}
	if _, queued := h.blacklist.entries[firstClaims.ID]; !queued {
		t.Fatalf("blacklist entries = %v, want the revoked JTI %q", h.blacklist.entries, firstClaims.ID)
	}
}

// A wrong verifier must still burn the code. Leaving it live would let a thief
// who stole the code brute-force verifiers against it.
func TestTokenAuthorizationCodeBurnsCodeOnFailedPKCE(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid")

	wrong := validCodeTokenInput(code)
	wrong.CodeVerifier = "cUvw2hM1Cq4pJZ8k1ZR5NnnP-3aFbxQ7yTgHkLmNoPq"
	_, err := h.service.Token(context.Background(), wrong)
	requireOAuthError(t, err, ErrorInvalidGrant)

	// The correct verifier must now fail too: the code is spent.
	_, err = h.service.Token(context.Background(), validCodeTokenInput(code))
	requireOAuthError(t, err, ErrorInvalidGrant)
	if h.tokens.createdAccess != nil {
		t.Fatal("a token pair was issued despite the failed PKCE check")
	}
}

func TestTokenAuthorizationCodeRejectsMismatchedBindings(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*TokenInput)
		wantCode string
	}{
		{
			name:     "redirect_uri differs from the authorization request",
			mutate:   func(i *TokenInput) { i.RedirectURI = "https://app.example.test/other" },
			wantCode: ErrorInvalidGrant,
		},
		{
			name:     "missing redirect_uri",
			mutate:   func(i *TokenInput) { i.RedirectURI = "" },
			wantCode: ErrorInvalidRequest,
		},
		{
			name:     "missing code_verifier",
			mutate:   func(i *TokenInput) { i.CodeVerifier = "" },
			wantCode: ErrorInvalidRequest,
		},
		{
			name:     "missing code",
			mutate:   func(i *TokenInput) { i.Code = "" },
			wantCode: ErrorInvalidRequest,
		},
		{
			name:     "unknown code",
			mutate:   func(i *TokenInput) { i.Code = "ac_nonexistent" },
			wantCode: ErrorInvalidGrant,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			code := issueCode(t, h, testPublicClientID, "openid")
			input := validCodeTokenInput(code)
			test.mutate(&input)
			_, err := h.service.Token(context.Background(), input)
			requireOAuthError(t, err, test.wantCode)
		})
	}
}

// A code issued to one client must not be redeemable by another, even when that
// other client authenticates correctly for itself.
func TestTokenAuthorizationCodeRejectsForeignClient(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid profile")

	input := validCodeTokenInput(code)
	input.ClientID = testConfidentialClientID
	input.ClientSecret = testClientSecret
	_, err := h.service.Token(context.Background(), input)
	requireOAuthError(t, err, ErrorInvalidGrant)
	if h.tokens.createdAccess != nil {
		t.Fatal("a foreign client redeemed another client's authorization code")
	}
}

func TestTokenAuthorizationCodeRejectsExpiredCode(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid")
	// Move the service clock past the code's 5-minute lifetime.
	h.service.Clock = fixedClock{value: h.clock.value.Add(6 * time.Minute)}

	_, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	oauthErr := oauthError(t, err, ErrorInvalidGrant)
	if !strings.Contains(oauthErr.Description, "过期") {
		t.Fatalf("description = %q, want it to name expiry", oauthErr.Description)
	}
	// An expired code was never redeemed, so nothing may be revoked for it.
	if len(h.tokens.revokedFamilies) != 0 {
		t.Fatalf("revoked families = %v, want none for a merely expired code", h.tokens.revokedFamilies)
	}
}

func TestTokenClientAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		secret   string
		wantCode string
	}{
		{
			name:     "public client with no secret",
			clientID: testPublicClientID,
			secret:   "",
			wantCode: "",
		},
		{
			// A public client presenting a secret is misconfigured about its own type;
			// accepting it silently would hide that.
			name:     "public client sending a secret",
			clientID: testPublicClientID,
			secret:   "unexpected",
			wantCode: ErrorInvalidClient,
		},
		{
			name:     "confidential client with correct secret",
			clientID: testConfidentialClientID,
			secret:   testClientSecret,
			wantCode: "",
		},
		{
			name:     "confidential client with wrong secret",
			clientID: testConfidentialClientID,
			secret:   "wrong-secret",
			wantCode: ErrorInvalidClient,
		},
		{
			name:     "confidential client with no secret",
			clientID: testConfidentialClientID,
			secret:   "",
			wantCode: ErrorInvalidClient,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			code := issueCode(t, h, test.clientID, "openid")
			input := validCodeTokenInput(code)
			input.ClientID = test.clientID
			input.ClientSecret = test.secret

			_, err := h.service.Token(context.Background(), input)
			if test.wantCode == "" {
				if err != nil {
					t.Fatalf("Token() error = %v, want success", err)
				}
				return
			}
			requireOAuthError(t, err, test.wantCode)
		})
	}

	// An unknown client cannot obtain a code in the first place, so it is checked
	// directly against a code issued to a real client. Client authentication must
	// fail before the code is even looked at.
	t.Run("unknown client", func(t *testing.T) {
		h := newHarness(t)
		code := issueCode(t, h, testPublicClientID, "openid")
		input := validCodeTokenInput(code)
		input.ClientID = "no-such-client"

		_, err := h.service.Token(context.Background(), input)
		requireOAuthError(t, err, ErrorInvalidClient)
		// The code must survive: a failed client authentication is not a redemption,
		// and burning the code here would let anyone invalidate a pending grant.
		if h.authorizations.byCode[code].IsUsed {
			t.Fatal("failed client authentication consumed the authorization code")
		}
	})
}

func TestTokenRejectsUnsupportedGrantType(t *testing.T) {
	h := newHarness(t)

	_, err := h.service.Token(context.Background(), TokenInput{GrantType: "password", ClientID: testPublicClientID})
	requireOAuthError(t, err, ErrorUnsupportedGrantType)

	_, err = h.service.Token(context.Background(), TokenInput{ClientID: testPublicClientID})
	requireOAuthError(t, err, ErrorInvalidRequest)
}

func TestTokenRefreshGrantRotates(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid profile")
	first, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}

	rotated, err := h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testPublicClientID,
	})
	if err != nil {
		t.Fatalf("refresh grant error = %v", err)
	}
	if rotated.RefreshToken == first.RefreshToken {
		t.Fatal("rotation returned the same refresh token")
	}
	if rotated.Scope != "openid profile" {
		t.Fatalf("rotated scope = %q, want the family's scopes unchanged", rotated.Scope)
	}
	if h.tokens.rotatedRefresh == nil || h.tokens.rotatedRefresh.Sequence != 1 {
		t.Fatalf("rotated refresh = %+v, want sequence 1", h.tokens.rotatedRefresh)
	}
	if h.tokens.rotatedRefresh.FamilyID != h.tokens.createdRefresh.FamilyID {
		t.Fatalf("rotated family = %q, want the original %q",
			h.tokens.rotatedRefresh.FamilyID, h.tokens.createdRefresh.FamilyID)
	}
	if rotated.IDToken == "" {
		t.Fatal("rotation returned no ID token")
	}
}

// Replaying an already-rotated refresh token is the classic stolen-token signal;
// the family must be cut rather than a new pair issued.
func TestTokenRefreshGrantReplayRevokesFamily(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid")
	first, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}
	familyID := h.tokens.createdRefresh.FamilyID

	if _, rotateErr := h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testPublicClientID,
	}); rotateErr != nil {
		t.Fatalf("first rotation error = %v", rotateErr)
	}

	_, err = h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testPublicClientID,
	})
	requireOAuthError(t, err, ErrorInvalidGrant)
	if len(h.tokens.revokedFamilies) != 1 || h.tokens.revokedFamilies[0] != familyID {
		t.Fatalf("revoked families = %v, want %q", h.tokens.revokedFamilies, familyID)
	}
}

// A refresh token belongs to one client. This check is also what keeps the OAuth
// path and the internal session path from crossing.
func TestTokenRefreshGrantRejectsForeignClient(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid")
	first, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}

	_, err = h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testConfidentialClientID,
		ClientSecret: testClientSecret,
	})
	requireOAuthError(t, err, ErrorInvalidGrant)
	if len(h.tokens.revokedFamilies) != 0 {
		t.Fatal("a client mismatch revoked the family; only a replay should")
	}
}

func TestTokenRefreshGrantRejectsUnknownAndExpired(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid")
	first, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}

	// An empty token is a malformed request; an unknown or wrongly shaped one is an
	// invalid grant. All three must be indistinguishable from each other in terms
	// of what they reveal about which tokens exist.
	for _, token := range []string{"", "rt_unknown-value", "not-even-our-format"} {
		_, tokenErr := h.service.Token(context.Background(), TokenInput{
			GrantType:    grantTypeRefreshToken,
			RefreshToken: token,
			ClientID:     testPublicClientID,
		})
		if tokenErr == nil {
			t.Fatalf("Token(refresh %q) returned no error", token)
		}
		var oauthErr *Error
		if !errors.As(tokenErr, &oauthErr) {
			t.Fatalf("error = %v, want *oauth.Error", tokenErr)
		}
	}

	h.service.Clock = fixedClock{value: h.clock.value.Add(31 * 24 * time.Hour)}
	_, err = h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testPublicClientID,
	})
	requireOAuthError(t, err, ErrorInvalidGrant)
}

func TestTokenRejectsClientWithoutRefreshGrant(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid")
	first, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}
	h.clients.byClientID[testPublicClientID].GrantTypes = model.StringArray{grantTypeAuthorizationCode}

	_, err = h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testPublicClientID,
	})
	requireOAuthError(t, err, ErrorUnauthorizedClient)
}

func TestTokenRejectsDeletedAccountOnRedemption(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid")
	h.users.byID[1].State = model.UserStateDeleted

	_, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	requireOAuthError(t, err, ErrorInvalidGrant)
	if h.tokens.createdAccess != nil {
		t.Fatal("a deleted account received a token pair")
	}
}

// If persistence succeeds but signing the ID token fails, the already-stored pair
// must be revoked: the client never learned about it, so leaving it live would
// create a session nobody can end.
func TestTokenRevokesPairWhenIDTokenSigningFails(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid profile")
	h.profiles.err = errors.New("profile read failed")

	_, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	requireOAuthError(t, err, ErrorServerError)
	if len(h.tokens.revokedFamilies) != 1 {
		t.Fatalf("revoked families = %v, want the orphaned pair's family revoked", h.tokens.revokedFamilies)
	}
}

func TestTokenSurfacesRepositoryFailures(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid")
	h.tokens.createErr = errors.New("insert failed")

	_, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	requireOAuthError(t, err, ErrorServerError)

	other := newHarness(t)
	otherCode := issueCode(t, other, testPublicClientID, "openid")
	other.authorizations.consumeAs = errors.New("database down")
	_, err = other.service.Token(context.Background(), validCodeTokenInput(otherCode))
	requireOAuthError(t, err, ErrorServerError)
}

func TestTokenTreatsRotationReplayErrorAsInvalidGrant(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid")
	first, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}
	h.tokens.rotateErr = repository.ErrTokenReplay

	_, err = h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testPublicClientID,
	})
	requireOAuthError(t, err, ErrorInvalidGrant)
	if len(h.tokens.revokedFamilies) != 1 {
		t.Fatalf("revoked families = %v, want the family revoked on a rotation replay", h.tokens.revokedFamilies)
	}
}

// parseIDTokenClaims verifies an ID token with the harness's signing key.
//
// It deliberately does not use VerifyAccessToken: that method enforces this
// service's own audience, which an ID token must not carry. The signature is
// still checked, so a token that failed to sign correctly would not pass here.
func parseIDTokenClaims(t *testing.T, h *harness, idToken string) *auth.IDTokenClaims {
	t.Helper()
	claims := &auth.IDTokenClaims{}
	parsed, err := jwt.ParseWithClaims(idToken, claims,
		func(*jwt.Token) (any, error) { return &h.service.JWT.Active.Private.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithTimeFunc(func() time.Time { return h.clock.value }),
	)
	if err != nil {
		t.Fatalf("parse ID token: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("parsed ID token is not valid")
	}
	return claims
}
