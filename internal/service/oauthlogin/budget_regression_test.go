package oauthlogin

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/provider"
)

type reviewLocalDoer struct {
	client *http.Client
	target *url.URL
}

func (d reviewLocalDoer) Do(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = d.target.Scheme
	u.Host = d.target.Host
	copy.URL = &u
	return d.client.Do(copy) // #nosec G704 -- Test-only transport rewrites to its own httptest server.
}
func TestRegressionCallbackRespondsWithinServerWriteTimeout(t *testing.T) {
	var hops atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hop := hops.Add(1)
		select {
		case <-r.Context().Done():
			return
		case <-time.After(3500 * time.Millisecond):
		}
		w.Header().Set("Content-Type", "application/json")
		switch hop {
		case 1:
			w.WriteHeader(502)
			_, _ = io.WriteString(w, `{"error":"upstream"}`)
		case 2:
			_, _ = io.WriteString(w, `{"access_token":"fixture-token"}`)
		default:
			_, _ = io.WriteString(w, `{"id":145339646,"login":"fixture"}`)
		}
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	service, doubles := newTestService(t)
	service.Providers[model.LoginMethodGitHub] = provider.NewGitHub(provider.GitHubConfig{ClientID: "fixture", ClientSecret: "fixture", RedirectURI: "https://example.test/callback"}, reviewLocalDoer{upstream.Client(), target}, nil)
	doubles.Users.byID[42] = activeUser(42)
	doubles.Identities.put(&model.Identity{UserID: 42, Provider: model.LoginMethodGitHub, ProviderID: "145339646"})
	state, digest := authorizedState(t, service)
	done := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		result, err := service.Callback(r.Context(), CallbackInput{Provider: model.LoginMethodGitHub, Code: "fixture-code", State: state, StateCookie: digest})
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Location", "https://example.test/done?login_code="+result.LoginCode)
		w.WriteHeader(http.StatusFound)
	}))
	server.Config.WriteTimeout = 10 * time.Second // cmd/api/server.go ServerWriteTimeout
	server.Start()
	defer server.Close()
	client := server.Client()
	client.Timeout = 20 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	start := time.Now()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	<-done
	status := 0
	if response != nil {
		status = response.StatusCode
		_ = response.Body.Close()
	}
	t.Logf("elapsed=%s hops=%d status=%d client_error=%v states_remaining=%d login_codes_written=%d", time.Since(start).Round(time.Millisecond), hops.Load(), status, err, len(doubles.States.states), len(doubles.LoginCodes.codes))
	if err != nil {
		t.Error("callback produced no HTTP response within server WriteTimeout")
	}
}

type reviewDeadlineProvider struct{ fakeProvider }

func (p *reviewDeadlineProvider) Exchange(ctx context.Context, _, _ string) (*provider.Identity, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type reviewContextStates struct{ *fakeStateStore }

func (s reviewContextStates) SaveOAuthState(ctx context.Context, state string, payload StatePayload, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.fakeStateStore.SaveOAuthState(ctx, state, payload, ttl)
}
func TestRegressionCallbackBudgetStillRestoresState(t *testing.T) {
	service, doubles := newTestService(t)
	service.States = reviewContextStates{doubles.States}
	service.Providers[model.LoginMethodGitHub] = &reviewDeadlineProvider{fakeProvider{authorizeURL: "https://example.test/authorize"}}
	state, digest := authorizedState(t, service)
	_, err := service.Callback(context.Background(), CallbackInput{Provider: model.LoginMethodGitHub, Code: "fixture-code", State: state, StateCookie: digest})
	_, restored := doubles.States.states[state]
	t.Logf("restorable=%t restored=%t error=%v", isRestorableOutcome(err), restored, err)
	if !restored {
		t.Error("callback budget expiry prevented restoring the consumed state because recovery reused the expired context")
	}
}

func TestRegressionRestoreFailureClearsRetryCookieFlag(t *testing.T) {
	service, doubles := newTestService(t)
	state, digest := authorizedState(t, service)
	doubles.States.saveErr = errors.New("redis write unavailable")
	doubles.GitHub.err = context.DeadlineExceeded
	_, err := service.Callback(context.Background(), CallbackInput{Provider: model.LoginMethodGitHub, Code: "code", State: state, StateCookie: digest})
	if isRestorableOutcome(err) {
		t.Fatalf("restore failed but response preserves retry cookie: %v", err)
	}
}

func TestRegressionCleanupKeepsAbsoluteRequestDeadline(t *testing.T) {
	ctx, cancel := WithRequestBudget(context.Background())
	defer cancel()
	original, _ := ctx.Deadline()
	ctx, cancelWork := workBudget(ctx)
	cancelWork()
	cleanup, stop := cleanupBudget(ctx)
	defer stop()
	if cleanup.Err() != nil {
		t.Fatal("cleanup inherited work cancellation")
	}
	deadline, _ := cleanup.Deadline()
	if deadline.After(original) || time.Until(deadline) > 510*time.Millisecond {
		t.Fatalf("cleanup deadline=%v original=%v", deadline, original)
	}
}
