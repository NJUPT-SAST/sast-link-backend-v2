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

// The silent mint shares the consent submission's per-user budget: it issues
// codes, so it may not sit outside the throttle.
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
