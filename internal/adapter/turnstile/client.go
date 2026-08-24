// Package turnstile verifies Cloudflare Turnstile tokens through the siteverify
// API.
//
// This guards the one unauthenticated write endpoint in the service: alumni
// account-request submission. Everything else either requires a bearer token or
// only sends a verification code to an address the caller must already control.
package turnstile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// siteverifyURL is Cloudflare's token validation endpoint.
const siteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// defaultTimeout bounds one siteverify round trip.
//
// A challenge token is valid for 300 seconds, so there is no value in waiting
// long: a submitter whose verification takes more than a few seconds is better
// served by an error they can retry than by a request that eventually succeeds
// after they have given up. The bound also keeps a hung Cloudflare from pinning
// request goroutines.
const defaultTimeout = 5 * time.Second

// maxResponseBytes caps the siteverify response read. The document is a small
// JSON object; anything larger is a misrouted response or a hostile proxy, and
// reading it unbounded would let that party choose our memory use.
const maxResponseBytes = 64 << 10

// maxTokenBytes is Cloudflare's documented ceiling for a challenge token.
// Rejecting an over-long token locally avoids paying for a round trip that
// cannot succeed, and keeps an arbitrary-length body out of the outbound
// request.
const maxTokenBytes = 2048

// ErrUnavailable reports that the verification could not be performed: no secret
// configured, the endpoint unreachable, a timeout, or a malformed response.
//
// Distinct from a verification failure because the two are opposite instructions
// to the caller. A failure means the submitter should solve the challenge again.
// Unavailable means nothing the submitter does will help, and the endpoint should
// refuse the request outright rather than telling them to retry a widget that is
// working correctly.
var ErrUnavailable = errors.New("turnstile: verification unavailable")

// ErrFailed reports that the token was rejected: absent, malformed, expired,
// already redeemed, or issued for a different action.
var ErrFailed = errors.New("turnstile: token rejected")

// Config carries the Turnstile settings. internal/config has already validated
// the shape; this struct only fails when the values cannot form a verifier.
type Config struct {
	// Secret is the widget's secret key. Required.
	Secret string
	// ExpectedAction, when set, must equal the action the token was issued for.
	//
	// Without this check any token minted under the same secret is accepted here,
	// so a token harvested from a different form on the same site would pass. The
	// widget sets the action client-side, which is why this is a match rather than
	// a trust: it does not prove intent, it only stops a token from one context
	// being spent in another.
	ExpectedAction string
	// Timeout bounds one siteverify call. Zero means defaultTimeout.
	Timeout time.Duration
}

// Client verifies tokens against the siteverify API.
type Client struct {
	secret         string
	expectedAction string
	endpoint       string
	httpClient     *http.Client
}

// New builds a verifier.
//
// An empty secret is refused rather than accepted as "verification disabled".
// The composition root decides what to do without a secret, and what it must not
// do is hand out a verifier that silently passes everything: this is the only
// check standing in front of an anonymous write.
func New(cfg Config) (*Client, error) {
	secret := strings.TrimSpace(cfg.Secret)
	if secret == "" {
		return nil, fmt.Errorf("turnstile: secret is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		secret:         secret,
		expectedAction: strings.TrimSpace(cfg.ExpectedAction),
		endpoint:       siteverifyURL,
		// An explicit client rather than http.DefaultClient, which has no timeout:
		// a Cloudflare side that accepts the connection and never answers would
		// hold the request goroutine until the caller's context is cancelled.
		httpClient: &http.Client{Timeout: timeout},
	}, nil
}

// siteverifyResponse is the documented response shape. Only the fields this
// decision needs are decoded.
type siteverifyResponse struct {
	Success    bool     `json:"success"`
	Action     string   `json:"action"`
	ErrorCodes []string `json:"error-codes"`
}

// Verify checks one token, returning nil when it is valid.
//
// Errors wrap ErrFailed when the token was rejected and ErrUnavailable when the
// check could not be made. Callers must distinguish the two: they map onto a 400
// and a 503 respectively.
//
// remoteIP is optional context for Cloudflare's own risk scoring; an empty value
// is omitted rather than sent blank.
//
// No retry. A token is single-use, so a timed-out attempt may or may not have
// been redeemed on Cloudflare's side, and a second attempt with the same token
// would likely come back timeout-or-duplicate - turning a network blip into
// "you failed the challenge", which tells the submitter to fix something that is
// not broken.
func (c *Client) Verify(ctx context.Context, token, remoteIP string) error {
	if c == nil {
		return fmt.Errorf("%w: nil client", ErrUnavailable)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("%w: empty token", ErrFailed)
	}
	if len(token) > maxTokenBytes {
		return fmt.Errorf("%w: token exceeds %d bytes", ErrFailed, maxTokenBytes)
	}

	form := url.Values{}
	form.Set("secret", c.secret)
	form.Set("response", token)
	if remote := strings.TrimSpace(remoteIP); remote != "" {
		form.Set("remoteip", remote)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: build request: %w", ErrUnavailable, err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() {
		// Drain before closing so the connection can be reused, and ignore the
		// error: the verdict has already been read or has already failed.
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		// A non-200 is Cloudflare's problem, not the submitter's: it says nothing
		// about the token, so it must not be reported as a failed challenge.
		return fmt.Errorf("%w: siteverify status %d", ErrUnavailable, response.StatusCode)
	}

	var decoded siteverifyResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes)).
		Decode(&decoded); err != nil {
		return fmt.Errorf("%w: decode response: %w", ErrUnavailable, err)
	}

	if !decoded.Success {
		return fmt.Errorf("%w: %s", ErrFailed, strings.Join(decoded.ErrorCodes, ","))
	}
	if c.expectedAction != "" && decoded.Action != c.expectedAction {
		return fmt.Errorf("%w: action %q, want %q", ErrFailed, decoded.Action, c.expectedAction)
	}
	return nil
}

// Unavailable is a verifier that refuses every token.
//
// Injected when no secret is configured, in place of leaving the dependency nil.
// A nil verifier has to be guarded at each call site, and the failure mode of a
// missed guard is that an anonymous write proceeds unverified. This one cannot be
// missed: it fails closed by construction.
type Unavailable struct{}

// Verify always reports ErrUnavailable.
func (Unavailable) Verify(context.Context, string, string) error {
	return fmt.Errorf("%w: no secret configured", ErrUnavailable)
}
