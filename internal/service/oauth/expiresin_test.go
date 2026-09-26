package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

// idTokenExpiry parses a signed ID Token and returns its exp. OIDC clients
// build sessions on this claim, so it must sit inside the same boundary the
// access token was clamped to, not the full configured TTL.
func idTokenExpiry(t *testing.T, h *harness, token string) time.Time {
	t.Helper()
	claims := &auth.IDTokenClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) {
		return h.service.JWT.Active.Private.Public(), nil
	}, jwt.WithTimeFunc(func() time.Time { return h.clock.value }))
	if err != nil || !parsed.Valid {
		t.Fatalf("parse ID token: %v", err)
	}
	if claims.ExpiresAt == nil {
		t.Fatal("ID token has no exp")
	}
	return claims.ExpiresAt.Time
}

// expires_in must describe the token that was actually signed. A capability
// family's access TTL is clamped to the delegation boundary, so the response
// cannot keep advertising the configured TTL while the JWT and the persisted row
// expire earlier: a client caching on expires_in would present a dead token.
func TestTokenAuthorizationCodeReportsClampedExpiresIn(t *testing.T) {
	h := newHarness(t)
	// The cap is far shorter than the configured access TTL, so the clamp is what
	// decides the answer.
	h.service.CapabilityRefreshMaxLifetime = 10 * time.Minute
	h.clients.byClientID[testConfidentialClientID].Scopes = model.StringArray{scope.OpenID, scope.AdminWrite}

	code := issueCode(t, h, testConfidentialClientID, "openid admin:write")
	result, err := h.service.Token(context.Background(), TokenInput{
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
	if result.ExpiresIn != 600 {
		t.Fatalf("expires_in = %d, want 600 (the cap), not the configured 3600", result.ExpiresIn)
	}
	// The three sources must agree: the signed JWT, the row, and the response.
	claims, err := h.service.JWT.VerifyAccessToken(result.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.ExpiresAt == nil {
		t.Fatal("access token has no exp")
	}
	if h.tokens.createdAccess == nil {
		t.Fatal("no access row was persisted")
	}
	if !claims.ExpiresAt.Equal(h.tokens.createdAccess.ExpiresAt) {
		t.Fatalf("jwt exp = %v, row expiry = %v, want them equal",
			claims.ExpiresAt.Time, h.tokens.createdAccess.ExpiresAt)
	}
	if h.tokens.createdRefresh == nil {
		t.Fatal("no refresh row was persisted")
	}
	if want := h.tokens.createdRefresh.CreatedAt.Add(10 * time.Minute); !h.tokens.createdRefresh.ExpiresAt.Equal(want) {
		t.Fatalf("refresh expiry = %v, want origin+10m %v", h.tokens.createdRefresh.ExpiresAt, want)
	}
	// The id_token shares the clamped TTL: a relying party building its session
	// on its exp must not outlive the delegation the access token respects.
	if got := idTokenExpiry(t, h, result.IDToken); !got.Equal(h.tokens.createdAccess.ExpiresAt) {
		t.Fatalf("id_token exp = %v, want the clamped %v", got, h.tokens.createdAccess.ExpiresAt)
	}
}

// The refresh leg clamps the signed access TTL to the delegation boundary the
// rotated refresh token already carries, so a refresh near the cap cannot mint
// an access token (or report an expires_in) past it.
func TestTokenRefreshReportsClampedExpiresIn(t *testing.T) {
	h := newHarness(t)
	h.service.CapabilityRefreshMaxLifetime = 7 * 24 * time.Hour
	h.clients.byClientID[testConfidentialClientID].Scopes = model.StringArray{scope.OpenID, scope.UserRead}

	code := issueCode(t, h, testConfidentialClientID, "openid user:read")
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

	// Bring the presented refresh token closer than the delegation deadline,
	// without moving the clock: its own expiry becomes the tighter bound.
	h.tokens.createdRefresh.ExpiresAt = h.clock.value.Add(5 * time.Minute)

	rotated, err := h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testConfidentialClientID,
		ClientSecret: testClientSecret,
	})
	if err != nil {
		t.Fatalf("refresh grant error = %v", err)
	}
	if rotated.ExpiresIn != 300 {
		t.Fatalf("expires_in = %d, want 300 (remaining delegation), not 3600", rotated.ExpiresIn)
	}
	claims, err := h.service.JWT.VerifyAccessToken(rotated.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.ExpiresAt == nil {
		t.Fatal("rotated access token has no exp")
	}
	if h.tokens.rotatedAccess == nil {
		t.Fatal("no rotated access row was persisted")
	}
	if !claims.ExpiresAt.Equal(h.tokens.rotatedAccess.ExpiresAt) {
		t.Fatalf("jwt exp = %v, rotated row expiry = %v, want them equal",
			claims.ExpiresAt.Time, h.tokens.rotatedAccess.ExpiresAt)
	}
	if got := idTokenExpiry(t, h, rotated.IDToken); !got.Equal(h.tokens.rotatedAccess.ExpiresAt) {
		t.Fatalf("id_token exp = %v, want the clamped %v", got, h.tokens.rotatedAccess.ExpiresAt)
	}
}

// A refresh row issued under a longer cap (or before the cap existed) carries
// its own expiry past the family's delegation deadline. The signed TTL must
// clamp to origin+cap, or the JWT would outlive the row the rotation
// transaction clamps — the exact disagreement the clamping exists to remove.
func TestTokenRefreshClampsToFamilyDeadlineOverLegacyRows(t *testing.T) {
	h := newHarness(t)
	h.service.CapabilityRefreshMaxLifetime = 7 * 24 * time.Hour
	h.clients.byClientID[testConfidentialClientID].Scopes = model.StringArray{scope.OpenID, scope.UserRead}

	code := issueCode(t, h, testConfidentialClientID, "openid user:read")
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

	// The legacy row outlives the delegation deadline.
	h.tokens.createdRefresh.ExpiresAt = h.clock.value.Add(30 * 24 * time.Hour)
	// Rotate near the boundary, where the configured access TTL would cross it.
	// Every clock the leg consults must move together: the service reads the
	// deadline, the signer stamps the exp, and the fake judges the cap.
	deadline := h.clock.value.Add(7 * 24 * time.Hour)
	rotated := h.clock.value.Add(7*24*time.Hour - 30*time.Minute)
	h.service.Clock = fixedClock{value: rotated}
	h.service.JWT.Clock = fixedClock{value: rotated}
	h.tokens.now = func() time.Time { return rotated }

	second, err := h.service.Token(context.Background(), TokenInput{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: first.RefreshToken,
		ClientID:     testConfidentialClientID,
		ClientSecret: testClientSecret,
	})
	if err != nil {
		t.Fatalf("refresh grant error = %v", err)
	}
	if second.ExpiresIn != 1800 {
		t.Fatalf("expires_in = %d, want 1800 (the 30m left to the deadline), not 3600", second.ExpiresIn)
	}
	claims, err := h.service.JWT.VerifyAccessToken(second.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.ExpiresAt == nil {
		t.Fatal("rotated access token has no exp")
	}
	if h.tokens.rotatedAccess == nil {
		t.Fatal("no rotated access row was persisted")
	}
	if !claims.ExpiresAt.Equal(deadline) {
		t.Fatalf("jwt exp = %v, want the family deadline %v", claims.ExpiresAt.Time, deadline)
	}
	if !h.tokens.rotatedAccess.ExpiresAt.Equal(deadline) {
		t.Fatalf("rotated row expiry = %v, want the family deadline %v", h.tokens.rotatedAccess.ExpiresAt, deadline)
	}
	if got := idTokenExpiry(t, h, second.IDToken); !got.Equal(deadline) {
		t.Fatalf("id_token exp = %v, want the family deadline %v", got, deadline)
	}
}
