package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

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

	// Bring the presented refresh token close to the boundary without moving the
	// clock: the service must read the delegation deadline off the token itself.
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
}
