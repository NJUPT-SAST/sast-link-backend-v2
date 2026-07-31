// Package provider implements the outbound HTTP clients for third-party OAuth
// logins (GitHub and Lark).
//
// Every call here talks to a network service the process does not control, so
// the package follows the same discipline as internal/mailer: a hard I/O
// timeout that applies even when the caller passes a context without a
// deadline, and failures reclassified through contextError so a cancelled
// caller is not reported as a provider outage.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Sentinel errors describe the failure classes a caller must distinguish. The
// service layer maps them onto business error codes; anything else is an
// internal error.
var (
	// ErrInvalidGrant means the provider rejected the authorization code. The
	// code was already used, expired, or was never issued to this client.
	ErrInvalidGrant = errors.New("provider rejected the authorization code")
	// ErrUnexpectedResponse means the provider answered in a shape this client
	// does not understand, including a missing required field.
	ErrUnexpectedResponse = errors.New("provider returned an unexpected response")
	// ErrForeignTenant means the account is outside the tenant this deployment
	// accepts. Only Lark returns it.
	ErrForeignTenant = errors.New("account belongs to a foreign tenant")
)

// httpIOTimeout bounds a single provider round trip. A provider that accepts
// the TCP connection and then stalls would otherwise hold a login request open
// for as long as the caller's context allows.
const httpIOTimeout = 10 * time.Second

// maxResponseBytes caps how much of a provider response is read. The payloads
// are small JSON objects; without a cap a misbehaving or hostile endpoint could
// stream until the process runs out of memory.
const maxResponseBytes = 1 << 20 // 1 MiB

// Identity is the normalized account description a provider returns. Providers
// differ in field names and in which identifier is stable, so each client
// resolves those differences before returning.
type Identity struct {
	// ProviderID is the stable, tenant-wide account identifier used as
	// identities.provider_id. It must not change between logins.
	ProviderID string
	// DisplayName and AvatarURL are echoed to the frontend on the
	// registration branch so a new account can prefill its profile.
	DisplayName string
	AvatarURL   string
	// Data becomes identities.identity_data. It carries the provider-specific
	// fields worth keeping for support and display.
	Data map[string]any
	// AccessToken, RefreshToken and TokenExpiresAt are the provider's own
	// credentials for this account, persisted so a future feature can call the
	// provider on the user's behalf. They are never returned to the client.
	AccessToken    string
	RefreshToken   string
	TokenExpiresAt *time.Time
}

// Doer is the HTTP client contract. It is an interface so tests can substitute
// a transport without a live provider.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// NewHTTPClient returns the HTTP client the provider clients use by default.
// The timeout is a backstop for the whole request including body reads; each
// request additionally derives a per-call context deadline.
func NewHTTPClient() *http.Client {
	return &http.Client{Timeout: httpIOTimeout}
}

// contextError reclassifies a transport failure. A caller that went away did
// not observe a provider outage, and reporting one would send a 502/503 for
// what is really a client disconnect.
func contextError(ctx context.Context, stage string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return fmt.Errorf("%s: %w", stage, err)
}

// doJSON issues req and decodes a JSON response body into target.
//
// It applies the I/O timeout even when ctx carries none, caps the body, and
// treats any non-2xx status as a failure. A non-2xx returns a *statusError,
// which wraps ErrUnexpectedResponse and keeps the status code so a caller can
// separate a provider's rejection of the input from a provider outage; see
// isClientRejection. A provider that signals a bad code with 200 plus an error
// field is handled by the caller inspecting the decoded payload.
func doJSON(ctx context.Context, client Doer, req *http.Request, stage string, target any) error {
	ctx, cancel := context.WithTimeout(ctx, httpIOTimeout)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return contextError(ctx, stage, err)
	}
	defer func() {
		// Drain before close so the connection can be reused; a bounded read
		// keeps a hostile endpoint from making the drain itself unbounded.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return contextError(ctx, stage+": read body", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The body often explains the rejection; keep a bounded excerpt so the
		// failure is diagnosable without logging a full payload. The status is
		// preserved in the error so a caller can separate "provider refused
		// this input" from "provider is unhealthy".
		return &statusError{
			StatusCode: resp.StatusCode,
			Stage:      stage,
			Excerpt:    bodyExcerpt(body),
		}
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("%s: decode body: %w", stage, ErrUnexpectedResponse)
	}
	return nil
}

// statusError carries the HTTP status alongside an ErrUnexpectedResponse wrap so
// a caller can tell a client-side rejection from a provider outage. Lark needs
// this: it answers a spent authorization code with 4xx rather than a body field.
type statusError struct {
	StatusCode int
	Stage      string
	Excerpt    string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%s: unexpected status %d: %s (%s)",
		e.Stage, e.StatusCode, ErrUnexpectedResponse.Error(), e.Excerpt)
}

// Unwrap ties statusError to ErrUnexpectedResponse so callers that only care
// about the class keep matching it with errors.Is.
func (e *statusError) Unwrap() error { return ErrUnexpectedResponse }

// isClientRejection reports whether err is a 4xx from the provider, i.e. the
// provider understood the request and refused it. A 5xx or a transport failure
// is the provider's problem and must stay an outage.
func isClientRejection(err error) bool {
	var status *statusError
	if !errors.As(err, &status) {
		return false
	}
	return status.StatusCode >= 400 && status.StatusCode <= 499
}

// bodyExcerpt trims a response body to a short single-line excerpt for error
// messages. Provider errors are descriptive but can be long, and a raw body may
// contain newlines that break log parsing.
func bodyExcerpt(body []byte) string {
	const limit = 256
	excerpt := strings.TrimSpace(string(body))
	excerpt = strings.ReplaceAll(excerpt, "\n", " ")
	excerpt = strings.ReplaceAll(excerpt, "\r", " ")
	if len(excerpt) > limit {
		return excerpt[:limit] + "..."
	}
	return excerpt
}

// expiryFromSeconds converts a provider's relative expires_in into an absolute
// instant. A non-positive value means the provider did not say, so the identity
// carries no expiry rather than one already in the past.
func expiryFromSeconds(now time.Time, seconds int) *time.Time {
	if seconds <= 0 {
		return nil
	}
	expires := now.Add(time.Duration(seconds) * time.Second)
	return &expires
}
