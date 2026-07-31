package oauthloginredis

import (
	"context"
	"testing"
	"time"

	sessionredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/adapter/redis/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauthlogin"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
)

func newTestStore(t *testing.T) internalredis.Store {
	t.Helper()
	client := testutil.StartRedis(t)
	return internalredis.Store{Client: client, Keys: internalredis.NewKeys("sastlink:test")}
}

func TestStateStoreRoundTripAndSingleUse(t *testing.T) {
	store := StateStore{Store: newTestStore(t)}
	ctx := context.Background()

	payload := oauthlogin.StatePayload{
		Provider: model.LoginMethodGitHub,
		Redirect: "https://link.sast.fun/callback",
	}
	if err := store.SaveOAuthState(ctx, "os_abc", payload, time.Minute); err != nil {
		t.Fatalf("SaveOAuthState: %v", err)
	}

	got, found, err := store.ConsumeOAuthState(ctx, "os_abc")
	if err != nil {
		t.Fatalf("ConsumeOAuthState: %v", err)
	}
	if !found {
		t.Fatal("state was not found")
	}
	if got.Provider != model.LoginMethodGitHub || got.Redirect != payload.Redirect {
		t.Fatalf("payload = %+v, want %+v", got, payload)
	}

	// GetDel semantics: a replayed callback finds nothing.
	if _, found, err = store.ConsumeOAuthState(ctx, "os_abc"); err != nil {
		t.Fatalf("second ConsumeOAuthState: %v", err)
	}
	if found {
		t.Fatal("state survived consumption")
	}
}

func TestStateStoreRefusesOverwrite(t *testing.T) {
	store := StateStore{Store: newTestStore(t)}
	ctx := context.Background()

	first := oauthlogin.StatePayload{Provider: model.LoginMethodGitHub}
	if err := store.SaveOAuthState(ctx, "os_abc", first, time.Minute); err != nil {
		t.Fatalf("first save: %v", err)
	}
	// SET NX: refusing keeps one state bound to one provider and redirect rather
	// than letting a second call retarget a pending login.
	second := oauthlogin.StatePayload{Provider: model.LoginMethodLark}
	if err := store.SaveOAuthState(ctx, "os_abc", second, time.Minute); err == nil {
		t.Fatal("overwriting a live state succeeded, want ErrAlreadyExists")
	}
}

func TestStateStoreMissingKeyIsNotAnError(t *testing.T) {
	store := StateStore{Store: newTestStore(t)}

	// An expired or forged state is an ordinary outcome, not a Redis failure:
	// the service answers it by asking the user to restart.
	_, found, err := store.ConsumeOAuthState(context.Background(), "os_missing")
	if err != nil {
		t.Fatalf("ConsumeOAuthState on a missing key returned %v, want nil", err)
	}
	if found {
		t.Fatal("found = true for a missing key")
	}
}

func TestLoginCodeStoreRoundTripPreservesUserID(t *testing.T) {
	store := LoginCodeStore{Store: newTestStore(t)}
	ctx := context.Background()

	// Above 2^53 to prove the ID is not routed through a JSON number, which
	// would silently lose precision.
	const userID int64 = 9007199254740993
	if err := store.SaveLoginCode(ctx, "lc_abc", userID, time.Minute); err != nil {
		t.Fatalf("SaveLoginCode: %v", err)
	}
	got, found, err := store.ConsumeLoginCode(ctx, "lc_abc")
	if err != nil {
		t.Fatalf("ConsumeLoginCode: %v", err)
	}
	if !found {
		t.Fatal("login code was not found")
	}
	if got != userID {
		t.Fatalf("user ID = %d, want %d", got, userID)
	}
	if _, found, _ = store.ConsumeLoginCode(ctx, "lc_abc"); found {
		t.Fatal("login code survived consumption")
	}
}

// The registration payload is written by this package and read back by the
// session service through a separate struct. Neither service package may import
// the other, so the JSON field tags are the only thing keeping them compatible.
// This is the test that catches a tag rename on one side.
func TestRegistrationStateIsReadableBySessionService(t *testing.T) {
	store := newTestStore(t)
	writer := RegistrationStateStore{Store: store}
	reader := sessionredis.OAuthRegistrationStore{Store: store}
	ctx := context.Background()

	expires := time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC)
	written := oauthlogin.RegistrationPayload{
		Provider:       model.LoginMethodGitHub,
		ProviderID:     "145339646",
		IdentityData:   model.JSONB(`{"login":"ptilopsis"}`),
		OAuthState:     "os_abc",
		AccessToken:    "gho_token",
		RefreshToken:   "ghr_token",
		TokenExpiresAt: &expires,
	}
	if err := writer.SaveRegistrationState(ctx, "rs_abc", written, time.Minute); err != nil {
		t.Fatalf("SaveRegistrationState: %v", err)
	}

	got, found, err := reader.ConsumeRegistrationState(ctx, "rs_abc")
	if err != nil {
		t.Fatalf("ConsumeRegistrationState: %v", err)
	}
	if !found {
		t.Fatal("registration state was not found by the session-side reader")
	}
	if got.Provider != written.Provider {
		t.Fatalf("provider = %q, want %q", got.Provider, written.Provider)
	}
	if got.ProviderID != written.ProviderID {
		t.Fatalf("provider_id = %q, want %q", got.ProviderID, written.ProviderID)
	}
	// The double binding depends on this field surviving the round trip; if it
	// arrived empty, every OAuth registration would fail the state comparison.
	if got.OAuthState != written.OAuthState {
		t.Fatalf("oauth_state = %q, want %q", got.OAuthState, written.OAuthState)
	}
	if string(got.IdentityData) != string(written.IdentityData) {
		t.Fatalf("identity_data = %s, want %s", got.IdentityData, written.IdentityData)
	}
	if got.AccessToken != written.AccessToken || got.RefreshToken != written.RefreshToken {
		t.Fatalf("provider tokens = %q/%q, want %q/%q",
			got.AccessToken, got.RefreshToken, written.AccessToken, written.RefreshToken)
	}
	if got.TokenExpiresAt == nil || !got.TokenExpiresAt.Equal(expires) {
		t.Fatalf("token_expires_at = %v, want %v", got.TokenExpiresAt, expires)
	}

	// One-time consumption holds across the package boundary too.
	if _, found, _ = reader.ConsumeRegistrationState(ctx, "rs_abc"); found {
		t.Fatal("registration state survived consumption")
	}
}

// Both packages must agree on the key, not just the payload. Writing through one
// and reading a hand-built key through the other proves the shared builder is
// what both use.
func TestRegistrationStateSharesOneKey(t *testing.T) {
	store := newTestStore(t)
	writer := RegistrationStateStore{Store: store}
	ctx := context.Background()

	if err := writer.SaveRegistrationState(ctx, "rs_key", oauthlogin.RegistrationPayload{
		Provider: model.LoginMethodLark, ProviderID: "on_union", OAuthState: "os_key",
	}, time.Minute); err != nil {
		t.Fatalf("SaveRegistrationState: %v", err)
	}

	var raw oauthlogin.RegistrationPayload
	if err := store.PeekOneTime(ctx, store.Keys.OAuthRegistration("rs_key"), &raw); err != nil {
		t.Fatalf("PeekOneTime on the shared key: %v", err)
	}
	if raw.ProviderID != "on_union" {
		t.Fatalf("provider_id = %q, want on_union", raw.ProviderID)
	}
}
