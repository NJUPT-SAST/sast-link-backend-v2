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
