package oauth

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// decisions collects the "decision" detail value from every oauth_authorize
// audit row, so a silent mint can be told from an interactive one.
func (f *fakeAudit) decisions() []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	decisions := make([]string, 0, len(f.entries))
	for _, entry := range f.entries {
		if entry.Action != "oauth_authorize" {
			continue
		}
		var detail map[string]any
		if err := json.Unmarshal(entry.Detail, &detail); err != nil {
			continue
		}
		if decision, ok := detail["decision"].(string); ok {
			decisions = append(decisions, decision)
		}
	}
	return decisions
}

// A user who has consented once completes later authorizations with the same
// client and scopes without the consent page: the silent path mints the code
// and the browser goes straight back to the client.
func TestSilentConsentIssuesCodeFromStandingGrant(t *testing.T) {
	h := newHarness(t)
	// One interactive consent establishes the standing grant, exactly as in
	// production where oauth_grants is written by the consent transaction.
	first, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("first Authorize() error = %v", err)
	}
	if _, consentErr := h.service.Consent(context.Background(), ConsentInput{
		RequestID: first.RequestID,
		Approve:   true,
		UserID:    1,
		ClientIP:  "203.0.113.10",
	}); consentErr != nil {
		t.Fatalf("interactive Consent() error = %v", consentErr)
	}

	second, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("second Authorize() error = %v", err)
	}
	result, err := h.service.SilentConsent(context.Background(), SilentConsentInput{
		RequestID: second.RequestID,
		UserID:    1,
		ClientIP:  "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("SilentConsent() error = %v", err)
	}

	parsed, err := url.Parse(result.RedirectURI)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	query := parsed.Query()
	if !strings.HasPrefix(query.Get("code"), authorizationCodePrefix) {
		t.Fatalf("code = %q, want a minted authorization code", query.Get("code"))
	}
	if query.Get("state") != "client-state" {
		t.Fatalf("state = %q, want the client's original value echoed back", query.Get("state"))
	}
	if query.Get("error") != "" {
		t.Fatalf("redirect carries error = %q on success", query.Get("error"))
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != testRedirectURI {
		t.Fatalf("redirect target = %q, want the registered redirect_uri", parsed.String())
	}
	if got := h.audit.decisions(); len(got) != 2 || got[0] != "granted" || got[1] != "granted_silent" {
		t.Fatalf("audit decisions = %v, want granted then granted_silent", got)
	}

	// The stash was consumed by the silent mint: a second attempt on the same
	// request fails rather than minting a second code.
	if _, err := h.service.SilentConsent(context.Background(), SilentConsentInput{
		RequestID: second.RequestID,
		UserID:    1,
	}); err == nil {
		t.Fatal("second SilentConsent() on the same stash succeeded; the stash must be single-use")
	} else {
		requireOAuthError(t, err, ErrorInvalidRequest)
	}
}

// Every silent refusal must leave the stash intact, so the consent page the
// caller falls back to can still submit the same pending request.
func TestSilentConsentFailureLeavesStashForConsentPage(t *testing.T) {
	t.Run("no grant with the client", func(t *testing.T) {
		h := newHarness(t)
		authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
		if err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}

		_, err = h.service.SilentConsent(context.Background(), SilentConsentInput{
			RequestID: authorized.RequestID,
			UserID:    1,
		})
		requireOAuthError(t, err, ErrorInvalidScope)

		// The interactive decision still works on the same request.
		result, err := h.service.Consent(context.Background(), ConsentInput{
			RequestID: authorized.RequestID,
			Approve:   true,
			UserID:    1,
		})
		if err != nil {
			t.Fatalf("Consent() after a silent refusal error = %v; the stash was spent", err)
		}
		if !strings.Contains(result.RedirectURI, "code=") {
			t.Fatalf("redirect = %q, want the interactive mint to succeed", result.RedirectURI)
		}
	})

	t.Run("grant narrower than the request", func(t *testing.T) {
		h := newHarness(t)
		h.authorizations.grantScopes[[2]int64{1, 10}] = model.StringArray{"openid"}
		authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t)) // openid profile email
		if err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}

		_, err = h.service.SilentConsent(context.Background(), SilentConsentInput{
			RequestID: authorized.RequestID,
			UserID:    1,
		})
		requireOAuthError(t, err, ErrorInvalidScope)
		if len(h.authorizations.created) != 0 {
			t.Fatal("a narrower grant silently minted a code")
		}
	})

	t.Run("client disabled between legs", func(t *testing.T) {
		h := newHarness(t)
		h.authorizations.grantScopes[[2]int64{1, 10}] = model.StringArray{"openid", "profile", "email"}
		authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
		if err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}
		h.clients.err = repository.ErrNotFound

		_, err = h.service.SilentConsent(context.Background(), SilentConsentInput{
			RequestID: authorized.RequestID,
			UserID:    1,
		})
		requireOAuthError(t, err, ErrorInvalidClient)
	})

	t.Run("grant lookup fails closed", func(t *testing.T) {
		h := newHarness(t)
		h.authorizations.grantScopes[[2]int64{1, 10}] = model.StringArray{"openid", "profile", "email"}
		h.authorizations.findGrantErr = repository.ErrInvalidArgument
		authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
		if err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}

		_, err = h.service.SilentConsent(context.Background(), SilentConsentInput{
			RequestID: authorized.RequestID,
			UserID:    1,
		})
		requireOAuthError(t, err, ErrorServerError)
	})
}

// The input contract mirrors Consent's: an absent subject or stash is rejected
// before anything is read or spent.
func TestSilentConsentRejectsUnknownStashAndBadPrincipal(t *testing.T) {
	h := newHarness(t)
	if _, err := h.service.SilentConsent(context.Background(), SilentConsentInput{RequestID: "ar_missing"}); err == nil {
		t.Fatal("userID 0 accepted")
	} else {
		requireOAuthError(t, err, ErrorInvalidToken)
	}
	if _, err := h.service.SilentConsent(context.Background(), SilentConsentInput{UserID: 1}); err == nil {
		t.Fatal("empty request_id accepted")
	} else {
		requireOAuthError(t, err, ErrorInvalidRequest)
	}
	if _, err := h.service.SilentConsent(context.Background(), SilentConsentInput{RequestID: "ar_missing", UserID: 1}); err == nil {
		t.Fatal("unknown stash accepted")
	} else {
		requireOAuthError(t, err, ErrorInvalidRequest)
	}
}

// The silent mint is throttled too — it issues codes, so it may not sit outside
// the limiter — but on its own scope, so the refusals it pays for cannot be
// charged against the allowance the consent page needs to submit.
func TestSilentConsentThrottlesByUser(t *testing.T) {
	h := newHarness(t)
	h.authorizations.grantScopes[[2]int64{1, 10}] = model.StringArray{"openid", "profile", "email"}
	// Seed the stash while the shared limiter still allows, then arm it.
	authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	h.limiter.result = LimitResult{Allowed: false, RetryAfter: time.Minute}

	_, err = h.service.SilentConsent(context.Background(), SilentConsentInput{
		RequestID: authorized.RequestID,
		UserID:    1,
	})
	oauthErr := oauthError(t, err, ErrorTemporarilyUnavail)
	if oauthErr.RetryAfter != time.Minute {
		t.Fatalf("Retry-After = %v, want the limiter's window", oauthErr.RetryAfter)
	}
	if len(h.authorizations.created) != 0 {
		t.Fatal("a throttled silent mint issued a code")
	}
	if calls := h.limiter.callsSnapshot(); len(calls) == 0 || calls[len(calls)-1] != "oauth_consent_silent:user:1" {
		t.Fatalf("limiter calls = %v, want the silent mint charged to its own bucket", calls)
	}
}

// The bucket split in both directions: a silent attempt must not spend the
// interactive consent allowance, and an interactive approval must not spend the
// silent one. A client bouncing the browser through /oauth/authorize often
// enough would otherwise leave the user unable to submit the page it fell back
// to, which is the one page that can still finish the authorization.
func TestSilentConsentAndInteractiveConsentKeepSeparateBudgets(t *testing.T) {
	h := newHarness(t)
	// No grant, so the silent attempt pays its own bucket and falls through to
	// the consent page without spending the stash.
	authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if _, err := h.service.SilentConsent(context.Background(), SilentConsentInput{
		RequestID: authorized.RequestID,
		UserID:    1,
	}); err == nil {
		t.Fatal("a silent attempt with no grant succeeded")
	}
	// The user then approves on the page they fell back to, and must not be
	// throttled by what the silent attempt just paid.
	if _, err := h.service.Consent(context.Background(), ConsentInput{
		RequestID: authorized.RequestID, UserID: 1, Approve: true,
	}); err != nil {
		t.Fatalf("Consent() error = %v, want the silent charge not to starve the interactive decision", err)
	}

	seen := map[string]bool{}
	for _, call := range h.limiter.callsSnapshot() {
		seen[strings.SplitN(call, ":", 2)[0]] = true
	}
	if !seen["oauth_consent"] || !seen["oauth_consent_silent"] {
		t.Fatalf("limiter calls = %v, want one charge to each bucket", h.limiter.callsSnapshot())
	}
}

// One stash yields at most one silent code; concurrent attempts on the same
// request cannot double-mint.
func TestSilentConsentConsumesStashExactlyOnce(t *testing.T) {
	h := newHarness(t)
	h.authorizations.grantScopes[[2]int64{1, 10}] = model.StringArray{"openid", "profile", "email"}
	authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	const contenders = 6
	start := make(chan struct{})
	results := make(chan error, contenders)
	var waitGroup sync.WaitGroup
	waitGroup.Add(contenders)
	for range contenders {
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := h.service.SilentConsent(context.Background(), SilentConsentInput{
				RequestID: authorized.RequestID,
				UserID:    1,
			})
			results <- err
		}()
	}
	close(start)
	waitGroup.Wait()

	successes := 0
	for range contenders {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("silent mints = %d, want exactly 1", successes)
	}
	if len(h.authorizations.created) != 1 {
		t.Fatalf("created authorizations = %d, want 1", len(h.authorizations.created))
	}
}

// prompt=login and prompt=consent ask for a fresh user gesture. Before the
// silent path existed every authorization rendered the consent page, so these
// were honored by accident; the silent leg has to honor them on purpose or it
// hands an RP the one thing the parameter exists to prevent.
func TestSilentConsentDefersToPromptForcingInteraction(t *testing.T) {
	for _, prompt := range []string{"consent", "login", "login consent", "select_account consent"} {
		t.Run("vetoes "+prompt, func(t *testing.T) {
			h := newHarness(t)
			h.authorizations.grantScopes[[2]int64{1, 10}] = model.StringArray{"openid", "profile", "email"}
			input := validAuthorizeInput(t)
			input.Prompt = prompt
			authorized, err := h.service.Authorize(context.Background(), input)
			if err != nil {
				t.Fatalf("Authorize() error = %v", err)
			}

			_, err = h.service.SilentConsent(context.Background(), SilentConsentInput{
				RequestID: authorized.RequestID,
				UserID:    1,
			})
			oauthErr := oauthError(t, err, ErrorInvalidRequest)
			if oauthErr.StashSpent {
				t.Fatal("a prompt veto spent the stash, want the consent page to still load it")
			}
			if len(h.authorizations.created) != 0 {
				t.Fatal("a prompt veto minted a code anyway")
			}
			// The page the browser is sent to can still complete the request.
			if _, err := h.service.Consent(context.Background(), ConsentInput{
				RequestID: authorized.RequestID, UserID: 1, Approve: true,
			}); err != nil {
				t.Fatalf("Consent() after a prompt veto error = %v", err)
			}
		})
	}

	// Values that do not demand a gesture must not veto: prompt=none asks for the
	// opposite, and an unknown value is better ignored than misread as its
	// opposite.
	for _, prompt := range []string{"", "none", "select_account"} {
		name := prompt
		if name == "" {
			name = "empty"
		}
		t.Run("ignores "+name, func(t *testing.T) {
			h := newHarness(t)
			h.authorizations.grantScopes[[2]int64{1, 10}] = model.StringArray{"openid", "profile", "email"}
			input := validAuthorizeInput(t)
			input.Prompt = prompt
			authorized, err := h.service.Authorize(context.Background(), input)
			if err != nil {
				t.Fatalf("Authorize() error = %v", err)
			}

			if _, err := h.service.SilentConsent(context.Background(), SilentConsentInput{
				RequestID: authorized.RequestID,
				UserID:    1,
			}); err != nil {
				t.Fatalf("SilentConsent() error = %v, want prompt %q not to veto the silent path", err, prompt)
			}
		})
	}
}

// The revoke that lands between the silent path's grant check and its write is
// the one the update-only writer exists for. CreateWithGrant would upsert the
// pair and put the deleted grant straight back, so the app would reappear in the
// authorized-apps list and the client would hold a live code — the user's revoke
// silently undone. The write must instead find nothing, roll the code back with
// it, and leave the caller knowing it has to start over.
func TestSilentConsentRefusesWhenTheGrantVanishesBeforeTheWrite(t *testing.T) {
	h := newHarness(t)
	h.authorizations.grantScopes[[2]int64{1, 10}] = model.StringArray{"openid", "profile", "email"}
	authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	// The revoke commits after the grant check read the row and before the mint
	// writes. The revoke does not touch the Redis stash, so the mint still runs.
	h.authorizations.deleteGrantsOnCreate = true

	_, err = h.service.SilentConsent(context.Background(), SilentConsentInput{
		RequestID: authorized.RequestID,
		UserID:    1,
	})
	oauthErr := oauthError(t, err, ErrorInvalidGrant)
	if !oauthErr.StashSpent {
		t.Fatal("the failed mint still reported the stash as reloadable, want a restart")
	}
	if len(h.authorizations.created) != 0 {
		t.Fatal("minted a code against a grant that had been revoked")
	}
	if _, found, err := h.authorizations.FindGrantScopes(context.Background(), 1, 10); err != nil {
		t.Fatalf("FindGrantScopes() error = %v", err)
	} else if found {
		t.Fatal("the revoked grant was recreated, want a silent mint never to create one")
	}
}

// A successful silent mint still refreshes the grant, so the authorized-apps
// list keeps showing the application the user consented to.
func TestSilentConsentRefreshesTheStandingGrant(t *testing.T) {
	h := newHarness(t)
	h.authorizations.grantScopes[[2]int64{1, 10}] = model.StringArray{"openid", "profile", "email"}
	authorized, err := h.service.Authorize(context.Background(), validAuthorizeInput(t))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if _, err := h.service.SilentConsent(context.Background(), SilentConsentInput{
		RequestID: authorized.RequestID,
		UserID:    1,
	}); err != nil {
		t.Fatalf("SilentConsent() error = %v", err)
	}
	if _, found, err := h.authorizations.FindGrantScopes(context.Background(), 1, 10); err != nil {
		t.Fatalf("FindGrantScopes() error = %v", err)
	} else if !found {
		t.Fatal("the standing grant disappeared after a silent mint")
	}
}
