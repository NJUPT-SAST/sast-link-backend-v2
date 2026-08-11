package oauth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
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
	if actions := h.audit.actions(); len(actions) != 1 || actions[0] != "oauth_authorize" {
		t.Fatalf("audit actions = %v, want oauth_authorize only (the token audit rides the pair transaction)", actions)
	}
	if len(h.tokens.auditEntries) != 1 || h.tokens.auditEntries[0].Action != "oauth_token" {
		t.Fatalf("token audit entries = %#v, want the oauth_token success audit in the pair transaction", h.tokens.auditEntries)
	}
	// The provider endpoints are addressed by client, so the row's actor is the
	// requesting client. Recording it in the column (not only in detail) is what makes
	// "everything this client did" one predicate across the admin and provider paths.
	if actor := h.tokens.auditEntries[0].ActorClientID; actor == nil || *actor != testPublicClientID {
		t.Fatalf("actor client id = %v, want the requesting client %q", actor, testPublicClientID)
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

// movingClock advances between calls, so a test can observe what a value is read
// from rather than only that it is plausible at one instant.
type movingClock struct{ now *time.Time }

func (c movingClock) Now() time.Time { return *c.now }

// Rotation is not a re-authentication, so auth_time must stay the instant the user
// authorized (PRD §4.10, API 文档 §5.3).
//
// Three rotations, not one: reading the *current* refresh row's created_at is
// correct for the first rotation and only starts drifting on the second, so a
// single-rotation test passes against the bug.
func TestTokenIDTokenAuthTimeSurvivesRepeatedRotation(t *testing.T) {
	h := newHarness(t)
	base := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	current := base
	h.service.Clock = movingClock{now: &current}

	code := issueCode(t, h, testPublicClientID, "openid")
	consentedAt := h.authorizations.created[0].CreatedAt

	issued, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}
	tokens := map[string]string{"code grant": issued.IDToken}
	refreshToken := issued.RefreshToken
	for i, elapsed := range []time.Duration{2 * time.Hour, 10 * time.Hour, 30 * time.Hour} {
		current = base.Add(elapsed)
		rotated, rotateErr := h.service.Token(context.Background(), TokenInput{
			GrantType:    grantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     testPublicClientID,
		})
		if rotateErr != nil {
			t.Fatalf("rotation %d error = %v", i+1, rotateErr)
		}
		tokens[fmt.Sprintf("rotation %d", i+1)] = rotated.IDToken
		refreshToken = rotated.RefreshToken
	}

	for name, token := range tokens {
		got := parseIDTokenClaims(t, h, token).AuthTime
		if got != consentedAt.Unix() {
			t.Errorf("%s auth_time = %v, want the authorization instant %v",
				name, time.Unix(got, 0).UTC(), consentedAt.UTC())
		}
	}
}

// The family always has a sequence-0 row, so a lookup failure means inconsistent
// metadata: refuse rather than sign an ID Token with a guessed auth_time.
func TestTokenRefreshFailsWhenFamilyOriginUnreadable(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid")
	issued, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}

	h.tokens.originErr = errors.New("database unavailable")
	_, err = h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: issued.RefreshToken,
		ClientID:     testPublicClientID,
	})
	if !errors.Is(err, ErrInternal) {
		t.Fatalf("Token() error = %v, want ErrInternal", err)
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
	if !slices.Contains(h.blacklist.jtis, firstClaims.ID) {
		t.Fatalf("blacklist entries = %v, want the revoked JTI %q", h.blacklist.jtis, firstClaims.ID)
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

// A code that belongs to another client must read identically to one that never
// existed. authenticateClient already hides client existence; this covers the
// grant-ownership check that runs after authentication succeeds, so a holder of a
// stolen code cannot probe which client it belongs to by watching the description.
func TestTokenAuthorizationCodeMismatchIsIndistinguishableFromUnknown(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid profile")

	// Both requests authenticate as the same confidential client, so the only
	// difference is whether the code exists at all or belongs to another client.
	unknownInput := validCodeTokenInput("ac_nonexistent")
	unknownInput.ClientID = testConfidentialClientID
	unknownInput.ClientSecret = testClientSecret
	_, unknownErr := h.service.Token(context.Background(), unknownInput)

	foreignInput := validCodeTokenInput(code)
	foreignInput.ClientID = testConfidentialClientID
	foreignInput.ClientSecret = testClientSecret
	_, foreignErr := h.service.Token(context.Background(), foreignInput)

	unknown := oauthError(t, unknownErr, ErrorInvalidGrant)
	foreign := oauthError(t, foreignErr, ErrorInvalidGrant)
	if foreign.Description != unknown.Description {
		t.Fatalf("foreign description = %q, unknown description = %q; a distinct message "+
			"lets a caller learn which client a stolen code belongs to",
			foreign.Description, unknown.Description)
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

// Client authentication must not reveal whether a client exists, nor how it is
// configured. client_id is public by design, so the risk is not enumeration: it is
// that two requests for a known client_id — one with a secret, one without — would
// otherwise report back whether it exists and whether it is public or confidential,
// and knowing a target is public (PKCE only, no secret) is useful to an attacker.
// Authorize already refuses to distinguish for the same reason.
func TestTokenClientAuthenticationFailuresAreIndistinguishable(t *testing.T) {
	cases := []struct {
		name     string
		clientID string
		secret   string
	}{
		{"unknown client", "no-such-client", ""},
		{"unknown client with a secret", "no-such-client", "guess"},
		{"public client sending a secret", testPublicClientID, "unexpected"},
		{"confidential client omitting its secret", testConfidentialClientID, ""},
		{"confidential client with a wrong secret", testConfidentialClientID, "wrong-secret"},
	}
	descriptions := make(map[string]string, len(cases))
	for _, test := range cases {
		h := newHarness(t)
		code := issueCode(t, h, testPublicClientID, "openid")
		input := validCodeTokenInput(code)
		input.ClientID = test.clientID
		input.ClientSecret = test.secret

		_, err := h.service.Token(context.Background(), input)

		var oauthErr *Error
		if !errors.As(err, &oauthErr) {
			t.Fatalf("%s: error = %v, want a typed *Error", test.name, err)
		}
		if oauthErr.Code != ErrorInvalidClient {
			t.Fatalf("%s: code = %q, want %q", test.name, oauthErr.Code, ErrorInvalidClient)
		}
		descriptions[test.name] = oauthErr.Description
	}
	// Every case must have produced the identical description.
	for name, description := range descriptions {
		if description != clientAuthFailed {
			t.Errorf("%s: description = %q, want the shared %q — a distinct message here "+
				"tells the caller whether the client exists and how it is configured",
				name, description, clientAuthFailed)
		}
	}
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

// A capability client may hold refresh_token: the refresh leg re-checks scopes
// against the live registration but never widens them. A confidential client
// holding admin:write refreshes and the new pair keeps the family's exact scope
// set — the grant door's relaxation (adminclient.checkCapabilityScopeGrant) must
// not let a refresh mint anything the family was not issued.
func TestTokenRefreshCapabilityClientKeepsFamilyScopes(t *testing.T) {
	h := newHarness(t)
	h.clients.byClientID[testConfidentialClientID].Scopes = model.StringArray{scope.OpenID, scope.AdminWrite}

	code := issueCode(t, h, testConfidentialClientID, "openid admin:write")
	first, err := h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeAuthorizationCode,
		Code:         code,
		RedirectURI:  testRedirectURI,
		ClientID:     testConfidentialClientID,
		ClientSecret: testClientSecret,
		CodeVerifier: testVerifier,
	})
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}

	rotated, err := h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testConfidentialClientID,
		ClientSecret: testClientSecret,
	})
	if err != nil {
		t.Fatalf("refresh grant error = %v", err)
	}
	if rotated.Scope != "openid admin:write" {
		t.Fatalf("rotated scope = %q, want the family's scopes unchanged", rotated.Scope)
	}
}

// A capability family's life is capped from its origin: the first refresh token
// is clamped to origin+cap at issuance, and every rotation clamps the rotated
// expiry to the same deadline instead of sliding it forward. A plain OIDC family
// is untouched.
func TestTokenRefreshCapabilityFamilyCappedAtLifetime(t *testing.T) {
	h := newHarness(t)
	h.service.CapabilityRefreshMaxLifetime = 7 * 24 * time.Hour
	h.clients.byClientID[testConfidentialClientID].Scopes = model.StringArray{scope.OpenID, scope.AdminWrite}

	code := issueCode(t, h, testConfidentialClientID, "openid admin:write")
	first, err := h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeAuthorizationCode,
		Code:         code,
		RedirectURI:  testRedirectURI,
		ClientID:     testConfidentialClientID,
		ClientSecret: testClientSecret,
		CodeVerifier: testVerifier,
	})
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}
	if h.tokens.createdRefresh == nil {
		t.Fatal("no first refresh token was minted")
	}
	origin := h.tokens.createdRefresh.CreatedAt
	if want := origin.Add(7 * 24 * time.Hour); !h.tokens.createdRefresh.ExpiresAt.Equal(want) {
		t.Fatalf("first refresh expiry = %v, want origin+7d %v (capped, not origin+30d)", h.tokens.createdRefresh.ExpiresAt, want)
	}

	rotated, err := h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testConfidentialClientID,
		ClientSecret: testClientSecret,
	})
	if err != nil {
		t.Fatalf("refresh grant error = %v", err)
	}
	if h.tokens.rotatedRefresh == nil {
		t.Fatal("no rotated refresh token was minted")
	}
	if want := origin.Add(7 * 24 * time.Hour); !h.tokens.rotatedRefresh.ExpiresAt.Equal(want) {
		t.Fatalf("rotated refresh expiry = %v, want origin+7d %v (clamped, not slid to origin+30d)", h.tokens.rotatedRefresh.ExpiresAt, want)
	}
	if rotated.Scope != "openid admin:write" {
		t.Fatalf("rotated scope = %q, want the family's scopes unchanged", rotated.Scope)
	}

	// The same cap must not reach a plain OIDC family: refresh its session scopes
	// and the expiry stays the uncapped sliding value.
	h.service.CapabilityRefreshMaxLifetime = 7 * 24 * time.Hour
	h.clients.byClientID[testPublicClientID].Scopes = model.StringArray{scope.OpenID, scope.Profile}
	code = issueCode(t, h, testPublicClientID, "openid profile")
	publicFirst, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("plain code grant error = %v", err)
	}
	if _, err := h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: publicFirst.RefreshToken,
		ClientID:     testPublicClientID,
	}); err != nil {
		t.Fatalf("plain refresh grant error = %v", err)
	}
	if want := h.tokens.createdRefresh.CreatedAt.Add(30 * 24 * time.Hour); h.tokens.rotatedRefresh.ExpiresAt.Before(want) {
		t.Fatalf("plain rotated refresh expiry = %v, want uncapped %v", h.tokens.rotatedRefresh.ExpiresAt, want)
	}
}

// A family whose origin predates the cap is revoked on the next refresh even
// though the presented token is still valid: the delegation outlived its
// lifetime and must be re-authorized, audited as refresh_family_expired rather
// than a replay.
func TestTokenRefreshCapabilityFamilyPastCapRevokes(t *testing.T) {
	h := newHarness(t)
	h.service.CapabilityRefreshMaxLifetime = 7 * 24 * time.Hour
	h.clients.byClientID[testConfidentialClientID].Scopes = model.StringArray{scope.OpenID, scope.AdminWrite}

	code := issueCode(t, h, testConfidentialClientID, "openid admin:write")
	first, err := h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeAuthorizationCode,
		Code:         code,
		RedirectURI:  testRedirectURI,
		ClientID:     testConfidentialClientID,
		ClientSecret: testClientSecret,
		CodeVerifier: testVerifier,
	})
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}
	// Rewind the family's origin to before the cap shipped, leaving the presented
	// token valid: exactly the migration shape of a pre-cap family.
	h.tokens.createdRefresh.CreatedAt = h.tokens.createdRefresh.CreatedAt.Add(-8 * 24 * time.Hour)

	_, err = h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testConfidentialClientID,
		ClientSecret: testClientSecret,
	})
	oauthErr := oauthError(t, err, ErrorInvalidGrant)
	if oauthErr.Kind != KindInvalidGrant {
		t.Fatalf("error = %+v, want invalid_grant so the client re-authorizes", oauthErr)
	}
	outcome := h.audit.outcomes()
	if !slices.Contains(outcome, "refresh_family_expired") {
		t.Fatalf("audit outcomes = %v, want a refresh_family_expired row", outcome)
	}
}

// A family's scopes were checked against the registration when its first pair was
// minted. If a change narrows the registration without going through the revoking
// update (a direct database edit, a future path), the refresh leg must stop
// minting the dropped scope rather than keep rotating it.
func TestTokenRefreshRejectsScopeNarrowedOutsideUpdate(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid profile")
	first, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}

	// The registration narrows behind the family's back, bypassing UpdateAndRevoke.
	h.clients.byClientID[testPublicClientID].Scopes = model.StringArray{"openid"}

	_, err = h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testPublicClientID,
	})
	requireOAuthError(t, err, ErrorInvalidScope)
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

	// Model a true replay: advance the clock past the grace window so the revoked
	// token reads as older than a benign concurrent refresh.
	current := time.Now().Add(repository.RefreshGracePeriod + time.Second)
	h.service.Clock = movingClock{now: &current}

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

// A concurrent refresh within the grace window is benign: the winning rotation
// preserved the family, so the losing request must not cut it or the winner is
// logged out (the two-tab case).
func TestTokenRefreshGraceWindowPreservesFamily(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid")
	first, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}

	if _, rotateErr := h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testPublicClientID,
	}); rotateErr != nil {
		t.Fatalf("first rotation error = %v", rotateErr)
	}

	// The replay lands within the grace window: report invalid, do not cut.
	_, err = h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testPublicClientID,
	})
	requireOAuthError(t, err, ErrorInvalidGrant)
	if len(h.tokens.revokedFamilies) != 0 {
		t.Fatalf("revoked families = %v, want the family preserved on a benign concurrent refresh", h.tokens.revokedFamilies)
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

// A refresh token that belongs to another client must read identically to one that
// never existed, for the same reason as the code check above.
func TestTokenRefreshMismatchIsIndistinguishableFromUnknown(t *testing.T) {
	h := newHarness(t)
	code := issueCode(t, h, testPublicClientID, "openid")
	first, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("code grant error = %v", err)
	}

	_, unknownErr := h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: "rt_nonexistent",
		ClientID:     testConfidentialClientID,
		ClientSecret: testClientSecret,
	})
	_, foreignErr := h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testConfidentialClientID,
		ClientSecret: testClientSecret,
	})

	unknown := oauthError(t, unknownErr, ErrorInvalidGrant)
	foreign := oauthError(t, foreignErr, ErrorInvalidGrant)
	if foreign.Description != unknown.Description {
		t.Fatalf("foreign description = %q, unknown description = %q; a distinct message "+
			"lets a caller learn which client a stolen refresh token belongs to",
			foreign.Description, unknown.Description)
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
	// The family decision belongs to the rotation transaction: it cuts the family
	// for a true replay and preserves it for a benign concurrent refresh (grace
	// window). The service must not re-revoke here, or it would log out the
	// winning side of a benign concurrent refresh.
	if len(h.tokens.revokedFamilies) != 0 {
		t.Fatalf("revoked families = %v, want the service to leave the family decision to the repository", h.tokens.revokedFamilies)
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
		func(*jwt.Token) (any, error) { return h.service.JWT.Active.Private.Public().(ed25519.PublicKey), nil },
		jwt.WithValidMethods([]string{"EdDSA"}),
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

// A code is minted before it is redeemed, so the consent-time re-check is only half
// the window. Without this one, revoking a client's delegated administration left
// every outstanding code redeemable for an administrative token until it expired.
func TestTokenAuthorizationCodeRejectsScopeRevokedAfterConsent(t *testing.T) {
	h := newHarness(t)
	delegated := h.clients.byClientID[testConfidentialClientID]
	delegated.Scopes = model.StringArray{"openid", scope.AdminWrite}

	code := issueCode(t, h, testConfidentialClientID, "openid "+scope.AdminWrite)

	// The operator revokes delegated administration between consent and redemption.
	delegated.Scopes = model.StringArray{"openid"}

	input := validCodeTokenInput(code)
	input.ClientID = testConfidentialClientID
	input.ClientSecret = testClientSecret
	_, err := h.service.Token(context.Background(), input)

	requireOAuthError(t, err, ErrorInvalidScope)
	if h.tokens.createdAccess != nil {
		t.Fatalf("an access token was issued despite the revoked scope: %#v", h.tokens.createdAccess)
	}
	// The code is still burned: this function consumes before it validates bindings, so
	// a rejection here must not leave a replayable code behind.
	if _, err := h.service.Token(context.Background(), input); err == nil {
		t.Fatal("the code survived a rejected redemption and was redeemable again")
	}
}
