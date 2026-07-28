package oauth

import (
	"context"
	"testing"
	"time"
)

// issuePair drives authorize + consent + token and returns the issued pair.
func issuePair(t *testing.T, h *harness) *TokenResult {
	t.Helper()
	code := issueCode(t, h, testPublicClientID, "openid profile")
	result, err := h.service.Token(context.Background(), validCodeTokenInput(code))
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	return result
}

func TestRevokeByRefreshTokenRevokesWholeFamily(t *testing.T) {
	h := newHarness(t)
	pair := issuePair(t, h)
	familyID := h.tokens.createdRefresh.FamilyID

	err := h.service.Revoke(context.Background(), RevokeInput{
		Token:         pair.RefreshToken,
		TokenTypeHint: "refresh_token",
		ClientID:      testPublicClientID,
		ClientIP:      "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if len(h.tokens.revokedFamilies) != 1 || h.tokens.revokedFamilies[0] != familyID {
		t.Fatalf("revoked families = %v, want %q", h.tokens.revokedFamilies, familyID)
	}
	// The sibling access token must go too, or it would stay valid for its full TTL
	// after the client asked for the session to end.
	claims, err := h.service.JWT.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if access := h.tokens.accessByJTI[claims.ID]; access == nil || access.RevokedAt == nil {
		t.Fatalf("access token = %+v, want revoked alongside its refresh token", access)
	}
	if _, queued := h.blacklist.entries[claims.ID]; !queued {
		t.Fatalf("blacklist = %v, want the revoked access JTI queued", h.blacklist.entries)
	}
}

// An access token is revocable too, and its jti must be taken from a verified
// signature: trusting an unverified JWT's claims would let anyone revoke an
// arbitrary family by forging a jti.
func TestRevokeByAccessTokenUsesVerifiedJTI(t *testing.T) {
	h := newHarness(t)
	pair := issuePair(t, h)
	familyID := h.tokens.createdRefresh.FamilyID

	err := h.service.Revoke(context.Background(), RevokeInput{
		Token:         pair.AccessToken,
		TokenTypeHint: tokenTypeHintAccess,
		ClientID:      testPublicClientID,
	})
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if len(h.tokens.revokedFamilies) != 1 || h.tokens.revokedFamilies[0] != familyID {
		t.Fatalf("revoked families = %v, want %q", h.tokens.revokedFamilies, familyID)
	}

	// A token signed by a different key must not resolve to any family.
	other := newHarness(t)
	otherPair := issuePair(t, other)
	fresh := newHarness(t)
	if err := fresh.service.Revoke(context.Background(), RevokeInput{
		Token:    otherPair.AccessToken,
		ClientID: testPublicClientID,
	}); err != nil {
		t.Fatalf("Revoke(foreign signature) error = %v, want RFC 7009 success", err)
	}
	if len(fresh.tokens.revokedFamilies) != 0 {
		t.Fatalf("revoked families = %v, want none for a token signed by another key", fresh.tokens.revokedFamilies)
	}
}

// A wrong token_type_hint only reorders the lookups; the token must still be
// revoked (RFC 7009 §2.1).
func TestRevokeIgnoresIncorrectTypeHint(t *testing.T) {
	h := newHarness(t)
	pair := issuePair(t, h)

	err := h.service.Revoke(context.Background(), RevokeInput{
		Token:         pair.RefreshToken,
		TokenTypeHint: tokenTypeHintAccess, // deliberately wrong
		ClientID:      testPublicClientID,
	})
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if len(h.tokens.revokedFamilies) != 1 {
		t.Fatalf("revoked families = %v, want the token revoked despite the wrong hint", h.tokens.revokedFamilies)
	}
}

// RFC 7009 §2.2: an unknown or already-invalid token is a success. Answering
// otherwise would make this endpoint an oracle for which token values exist.
func TestRevokeSucceedsForUnknownToken(t *testing.T) {
	h := newHarness(t)

	for _, token := range []string{"rt_unknown", "not-a-token", "ac_wrong-kind"} {
		if err := h.service.Revoke(context.Background(), RevokeInput{
			Token:    token,
			ClientID: testPublicClientID,
		}); err != nil {
			t.Fatalf("Revoke(%q) error = %v, want success", token, err)
		}
	}
	if len(h.tokens.revokedFamilies) != 0 {
		t.Fatalf("revoked families = %v, want none", h.tokens.revokedFamilies)
	}
	// Every call is still audited, so an unknown-token probe is visible.
	if actions := h.audit.actions(); len(actions) != 3 {
		t.Fatalf("audit actions = %v, want one per revoke attempt", actions)
	}
}

// One client must not be able to end another's sessions. A token it does not own
// reads as not-found, which is also the RFC-mandated answer.
func TestRevokeRejectsForeignClientToken(t *testing.T) {
	h := newHarness(t)
	pair := issuePair(t, h)

	err := h.service.Revoke(context.Background(), RevokeInput{
		Token:        pair.RefreshToken,
		ClientID:     testConfidentialClientID,
		ClientSecret: testClientSecret,
	})
	if err != nil {
		t.Fatalf("Revoke() error = %v, want RFC 7009 success", err)
	}
	if len(h.tokens.revokedFamilies) != 0 {
		t.Fatalf("revoked families = %v, want none: the token belongs to another client", h.tokens.revokedFamilies)
	}
}

func TestRevokeRequiresClientAuthenticationAndToken(t *testing.T) {
	h := newHarness(t)
	pair := issuePair(t, h)

	err := h.service.Revoke(context.Background(), RevokeInput{
		Token:        pair.RefreshToken,
		ClientID:     testConfidentialClientID,
		ClientSecret: "wrong",
	})
	requireOAuthError(t, err, ErrorInvalidClient)

	err = h.service.Revoke(context.Background(), RevokeInput{Token: "  ", ClientID: testPublicClientID})
	requireOAuthError(t, err, ErrorInvalidRequest)

	if len(h.tokens.revokedFamilies) != 0 {
		t.Fatalf("revoked families = %v, want none", h.tokens.revokedFamilies)
	}
}

// An expired access token is already ineffective, so RFC 7009 wants success and
// nothing to revoke.
func TestRevokeSucceedsForExpiredAccessToken(t *testing.T) {
	h := newHarness(t)
	pair := issuePair(t, h)
	h.service.Clock = fixedClock{value: h.clock.value.Add(2 * time.Hour)}

	if err := h.service.Revoke(context.Background(), RevokeInput{
		Token:    pair.AccessToken,
		ClientID: testPublicClientID,
	}); err != nil {
		t.Fatalf("Revoke(expired access token) error = %v, want success", err)
	}
}
