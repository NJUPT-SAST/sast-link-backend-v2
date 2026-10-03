package provider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// fakeDoer serves canned responses keyed by request URL prefix, recording the
// requests it saw so a test can assert on headers and bodies.
type fakeDoer struct {
	responses map[string]fakeResponse
	requests  []recordedRequest
	err       error
}

type fakeResponse struct {
	status int
	body   string
}

type recordedRequest struct {
	method string
	url    string
	header http.Header
	body   string
}

func (d *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	if d.err != nil {
		return nil, d.err
	}
	body := ""
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = string(raw)
	}
	d.requests = append(d.requests, recordedRequest{
		method: req.Method,
		url:    req.URL.String(),
		header: req.Header.Clone(),
		body:   body,
	})

	for prefix, response := range d.responses {
		if strings.HasPrefix(req.URL.String(), prefix) {
			return &http.Response{
				StatusCode: response.status,
				Body:       io.NopCloser(strings.NewReader(response.body)),
				Header:     make(http.Header),
			}, nil
		}
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader(`{"error":"no canned response"}`)),
		Header:     make(http.Header),
	}, nil
}

func fixedClock() func() time.Time {
	instant := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return instant }
}

func (d *fakeDoer) requestFor(t *testing.T, prefix string) recordedRequest {
	t.Helper()
	for _, req := range d.requests {
		if strings.HasPrefix(req.url, prefix) {
			return req
		}
	}
	t.Fatalf("no request recorded for prefix %q", prefix)
	return recordedRequest{}
}

func TestDoJSONRejectsNon2xxWithStatusPreserved(t *testing.T) {
	doer := &fakeDoer{responses: map[string]fakeResponse{
		"https://example.test": {status: http.StatusBadRequest, body: `{"error":"nope"}`},
	}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test/x", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	var target map[string]any
	err = doJSON(context.Background(), doer, req, "test stage", &target)
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("error = %v, want ErrUnexpectedResponse", err)
	}
	if !isClientRejection(err) {
		t.Fatalf("isClientRejection(%v) = false, want true for a 400", err)
	}
}

func TestDoJSONTreatsServerErrorAsOutageNotRejection(t *testing.T) {
	doer := &fakeDoer{responses: map[string]fakeResponse{
		"https://example.test": {status: http.StatusBadGateway, body: `upstream down`},
	}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test/x", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	var target map[string]any
	err = doJSON(context.Background(), doer, req, "test stage", &target)
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("error = %v, want ErrUnexpectedResponse", err)
	}
	// A 502 is the provider's fault. Classifying it as a client rejection would
	// turn a provider outage into "your login code is invalid".
	if isClientRejection(err) {
		t.Fatal("isClientRejection = true for a 502, want false")
	}
}

func TestDoJSONReportsContextErrorWhenCallerCancelled(t *testing.T) {
	doer := &fakeDoer{err: errors.New("transport failed")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test/x", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	var target map[string]any
	err = doJSON(ctx, doer, req, "test stage", &target)
	// A caller that went away must not be reported as a provider failure.
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestDoJSONRejectsMalformedBody(t *testing.T) {
	doer := &fakeDoer{responses: map[string]fakeResponse{
		"https://example.test": {status: http.StatusOK, body: `not json`},
	}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test/x", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	var target map[string]any
	if err := doJSON(context.Background(), doer, req, "test stage", &target); !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("error = %v, want ErrUnexpectedResponse", err)
	}
}

func TestExpiryFromSecondsOmitsNonPositive(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	if got := expiryFromSeconds(now, 0); got != nil {
		t.Fatalf("expiry for 0 seconds = %v, want nil", got)
	}
	if got := expiryFromSeconds(now, -5); got != nil {
		t.Fatalf("expiry for negative seconds = %v, want nil", got)
	}
	got := expiryFromSeconds(now, 3600)
	if got == nil || !got.Equal(now.Add(time.Hour)) {
		t.Fatalf("expiry = %v, want %v", got, now.Add(time.Hour))
	}
}

func TestBodyExcerptCollapsesNewlinesAndTruncates(t *testing.T) {
	excerpt := bodyExcerpt([]byte("line one\nline two\r\n"))
	if strings.ContainsAny(excerpt, "\n\r") {
		t.Fatalf("excerpt %q still contains newlines", excerpt)
	}
	long := bodyExcerpt([]byte(strings.Repeat("a", 500)))
	if !strings.HasSuffix(long, "...") || len(long) > 300 {
		t.Fatalf("excerpt was not truncated: len=%d", len(long))
	}
}

// scriptedAttempt is one outcome in a sequenceDoer's script: either a response
// or a transport error.
type scriptedAttempt struct {
	status int
	body   string
	err    error
}

// sequenceDoer serves attempts in order, regardless of URL, repeating the last
// one when the script runs dry. It exists for retry-path tests, which need the
// same request to fail once and then succeed.
type sequenceDoer struct {
	attempts []scriptedAttempt
	handled  int
	bodies   []string
}

func (d *sequenceDoer) Do(req *http.Request) (*http.Response, error) {
	body := ""
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = string(raw)
	}
	d.bodies = append(d.bodies, body)
	index := d.handled
	if index >= len(d.attempts) {
		index = len(d.attempts) - 1
	}
	d.handled++
	attempt := d.attempts[index]
	if attempt.err != nil {
		return nil, attempt.err
	}
	return &http.Response{
		StatusCode: attempt.status,
		Body:       io.NopCloser(strings.NewReader(attempt.body)),
		Header:     make(http.Header),
	}, nil
}

// retryTestRunner swaps the retry backoff for a negligible one and restores it,
// so retry tests run in milliseconds without changing production timing.
func retryTestRunner(t *testing.T) {
	t.Helper()
	previous := providerRetryBackoff
	providerRetryBackoff = time.Millisecond
	t.Cleanup(func() { providerRetryBackoff = previous })
}

func buildJSONRequest(body string) requestBuilder {
	return func() (*http.Request, error) {
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.test/x", reader)
		if err != nil {
			return nil, err
		}
		return req, nil
	}
}

// A transport failure on the first attempt is retried, and a provider that
// answers the second try turns the login into a success instead of an error
// page.
func TestDoJSONRetryRecoversAfterTransportFailure(t *testing.T) {
	retryTestRunner(t)
	doer := &sequenceDoer{attempts: []scriptedAttempt{
		{err: errors.New("connection reset by peer")},
		{status: http.StatusOK, body: `{"ok":true}`},
	}}
	var target struct {
		OK bool `json:"ok"`
	}
	if err := doJSONRetry(context.Background(), doer, buildJSONRequest("a=1"), "test stage", &target); err != nil {
		t.Fatalf("error = %v, want success on retry", err)
	}
	if !target.OK {
		t.Fatal("target was not decoded from the retried response")
	}
	if doer.handled != 2 {
		t.Fatalf("handled = %d attempts, want 2", doer.handled)
	}
}

// The retry must re-send the POST body: the first attempt consumed the
// original body reader, so the builder is invoked per attempt.
func TestDoJSONRetryRebuildsPostBodyPerAttempt(t *testing.T) {
	retryTestRunner(t)
	doer := &sequenceDoer{attempts: []scriptedAttempt{
		{err: errors.New("dial tcp: i/o timeout")},
		{status: http.StatusOK, body: `{"ok":true}`},
	}}
	var target map[string]any
	if err := doJSONRetry(context.Background(), doer, buildJSONRequest("code=abc"), "test stage", &target); err != nil {
		t.Fatalf("error = %v, want success on retry", err)
	}
	if len(doer.bodies) != 2 || doer.bodies[0] != "code=abc" || doer.bodies[1] != "code=abc" {
		t.Fatalf("bodies = %v, want the full body on every attempt", doer.bodies)
	}
}

// A 4xx is an answer, not a fault: re-asking the same question cannot change
// it, and burning a second round trip would only double the latency.
func TestDoJSONRetryDoesNotRetryClientRejection(t *testing.T) {
	retryTestRunner(t)
	doer := &sequenceDoer{attempts: []scriptedAttempt{
		{status: http.StatusBadRequest, body: `{"error":"nope"}`},
		{status: http.StatusOK, body: `{"ok":true}`},
	}}
	var target map[string]any
	err := doJSONRetry(context.Background(), doer, buildJSONRequest(""), "test stage", &target)
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("error = %v, want ErrUnexpectedResponse", err)
	}
	if doer.handled != 1 {
		t.Fatalf("handled = %d attempts, want no retry", doer.handled)
	}
}

// A 5xx is the provider's side failing, which is exactly what one retry is for.
func TestDoJSONRetryRetriesServerError(t *testing.T) {
	retryTestRunner(t)
	doer := &sequenceDoer{attempts: []scriptedAttempt{
		{status: http.StatusBadGateway, body: `upstream down`},
		{status: http.StatusOK, body: `{"ok":true}`},
	}}
	var target map[string]any
	if err := doJSONRetry(context.Background(), doer, buildJSONRequest(""), "test stage", &target); err != nil {
		t.Fatalf("error = %v, want success on retry", err)
	}
	if doer.handled != 2 {
		t.Fatalf("handled = %d attempts, want 2", doer.handled)
	}
}

// An unparseable 2xx body is a shape problem with this client, not a network
// hiccup; retrying cannot produce a different shape from the same provider.
func TestDoJSONRetryDoesNotRetryDecodeFailure(t *testing.T) {
	retryTestRunner(t)
	doer := &sequenceDoer{attempts: []scriptedAttempt{
		{status: http.StatusOK, body: `not json`},
		{status: http.StatusOK, body: `{"ok":true}`},
	}}
	var target map[string]any
	err := doJSONRetry(context.Background(), doer, buildJSONRequest(""), "test stage", &target)
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("error = %v, want ErrUnexpectedResponse", err)
	}
	if doer.handled != 1 {
		t.Fatalf("handled = %d attempts, want no retry", doer.handled)
	}
}

// A caller that went away must not trigger a retry: the request would run for
// an audience that no longer exists.
func TestDoJSONRetrySkipsRetryWhenCallerCancelled(t *testing.T) {
	retryTestRunner(t)
	doer := &sequenceDoer{attempts: []scriptedAttempt{
		{err: context.Canceled},
		{status: http.StatusOK, body: `{"ok":true}`},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	build := func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test/x", nil)
	}
	var target map[string]any
	err := doJSONRetry(ctx, doer, build, "test stage", &target)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if doer.handled != 1 {
		t.Fatalf("handled = %d attempts, want no retry", doer.handled)
	}
}

// A provider that stalls past the per-call timeout is retried — one slow round
// trip is not evidence the provider is down.
func TestDoJSONRetryRetriesPerCallTimeout(t *testing.T) {
	retryTestRunner(t)
	doer := &sequenceDoer{attempts: []scriptedAttempt{
		{err: context.DeadlineExceeded},
		{status: http.StatusOK, body: `{"ok":true}`},
	}}
	var target map[string]any
	if err := doJSONRetry(context.Background(), doer, buildJSONRequest(""), "test stage", &target); err != nil {
		t.Fatalf("error = %v, want success on retry", err)
	}
	if doer.handled != 2 {
		t.Fatalf("handled = %d attempts, want 2", doer.handled)
	}
}

// Two failures exhaust the retry: the second error is returned as-is, mapped
// by the service exactly like a first-attempt failure.
func TestDoJSONRetryGivesUpAfterSecondFailure(t *testing.T) {
	retryTestRunner(t)
	doer := &sequenceDoer{attempts: []scriptedAttempt{
		{err: errors.New("connection reset by peer")},
		{err: errors.New("connection reset by peer")},
		{status: http.StatusOK, body: `{"ok":true}`},
	}}
	var target map[string]any
	err := doJSONRetry(context.Background(), doer, buildJSONRequest(""), "test stage", &target)
	if err == nil {
		t.Fatal("error = nil, want the transport failure")
	}
	if doer.handled != 2 {
		t.Fatalf("handled = %d attempts, want exactly 2 (one retry)", doer.handled)
	}
}
