package oauth

import (
	"context"
	"errors"
	"slices"
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
	if !slices.Contains(h.blacklist.jtis, claims.ID) {
		t.Fatalf("blacklist = %v, want the revoked access JTI queued", h.blacklist.jtis)
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

// An expired access token still names a live family, so revoking it must cut the
// family rather than report success and do nothing.
//
// Revocation here is family-wide (see Revoke's doc comment): the presented token
// being useless does not make its sibling refresh token useless, and that one lives
// for the full refresh TTL — 30 days by default. An expired access token is also the
// ordinary state of an idle client that now wants to log out, so this is the common
// path, not an edge case.
//
// Both clocks have to move. JWTManager carries its own Clock, so advancing only
// s.Clock leaves VerifyAccessToken believing the token is still valid and the test
// silently exercises the unexpired path instead — which is what the earlier version
// of this test did while claiming to cover expiry.
func TestRevokeExpiredAccessTokenStillRevokesFamily(t *testing.T) {
	h := newHarness(t)
	pair := issuePair(t, h)
	familyID := h.tokens.createdRefresh.FamilyID
	later := fixedClock{value: h.clock.value.Add(2 * time.Hour)}
	h.service.Clock = later
	h.service.JWT.Clock = later

	// Guard the setup: if this still verifies, the test is not testing expiry.
	if _, err := h.service.JWT.VerifyAccessToken(pair.AccessToken); err == nil {
		t.Fatal("access token still verifies; the expired path is not under test")
	}

	if err := h.service.Revoke(context.Background(), RevokeInput{
		Token:    pair.AccessToken,
		ClientID: testPublicClientID,
	}); err != nil {
		t.Fatalf("Revoke(expired access token) error = %v, want success", err)
	}

	if len(h.tokens.revokedFamilies) != 1 || h.tokens.revokedFamilies[0] != familyID {
		t.Fatalf("revoked families = %v, want %q: the sibling refresh token would "+
			"otherwise stay live for its full TTL", h.tokens.revokedFamilies, familyID)
	}
}

// The relaxed expiry check must not become a way to revoke someone else's family.
// Ownership is decided against the database row, not the token, so a token belonging
// to another client reads as not-found even though it verifies.
func TestRevokeExpiredAccessTokenStillChecksClientOwnership(t *testing.T) {
	h := newHarness(t)
	pair := issuePair(t, h)
	later := fixedClock{value: h.clock.value.Add(2 * time.Hour)}
	h.service.Clock = later
	h.service.JWT.Clock = later

	// A different client presents the expired token.
	err := h.service.Revoke(context.Background(), RevokeInput{
		Token:        pair.AccessToken,
		ClientID:     testConfidentialClientID,
		ClientSecret: testClientSecret,
	})

	if err != nil {
		t.Fatalf("Revoke() error = %v, want RFC 7009 success for a foreign token", err)
	}
	if len(h.tokens.revokedFamilies) != 0 {
		t.Fatalf("revoked families = %v, want none: the token belongs to another client",
			h.tokens.revokedFamilies)
	}
}

// RFC 7009's success contract is that the token no longer works. Reporting 200 for
// a revocation that did not commit tells the client the session is gone while it
// stays live for its full TTL, and the client has no reason to retry.
func TestRevokeSurfacesRevocationFailure(t *testing.T) {
	h := newHarness(t)
	pair := issuePair(t, h)
	h.tokens.revokeErr = errors.New("database unavailable")

	err := h.service.Revoke(context.Background(), RevokeInput{
		Token:    pair.RefreshToken,
		ClientID: testPublicClientID,
		ClientIP: "203.0.113.10",
	})

	if !errors.Is(err, ErrInternal) {
		t.Fatalf("Revoke() error = %v, want ErrInternal", err)
	}
	// The audit trail must not claim a revocation that did not happen.
	if len(h.audit.entries) == 0 {
		t.Fatal("no audit entry for a failed revocation")
	}
	last := h.audit.entries[len(h.audit.entries)-1]
	if last.Success == nil || *last.Success {
		t.Fatalf("audit success = %v, want false for a failed revocation", last.Success)
	}
}

// Both endpoints that authenticate a client and resolve a presented token share one
// per-IP limiter, so neither offers an unlimited number of credential attempts.
func TestRevokeThrottlesByIP(t *testing.T) {
	h := newHarness(t)
	pair := issuePair(t, h)
	h.limiter.result = LimitResult{Allowed: false, RetryAfter: 30 * time.Second}

	err := h.service.Revoke(context.Background(), RevokeInput{
		Token:    pair.RefreshToken,
		ClientID: testPublicClientID,
		ClientIP: "203.0.113.10",
	})

	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Revoke() error = %v, want ErrRateLimited", err)
	}
}
