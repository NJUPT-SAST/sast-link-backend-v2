// Package oauthredis adapts Redis primitives to the OAuth service ports.
package oauthredis

import (
	"context"
	"errors"
	"time"

	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauth"
)

// EndpointLimiter adapts the fixed-window limiter to the OAuth service port.
type EndpointLimiter struct {
	Limiter internalredis.FixedWindowLimiter
}

// Allow reports the rate-limit decision for one endpoint and subject.
func (l EndpointLimiter) Allow(ctx context.Context, endpoint, subject string) (oauth.LimitResult, error) {
	result, err := l.Limiter.Allow(ctx, endpoint, subject)
	if err != nil {
		return oauth.LimitResult{}, err
	}
	return oauth.LimitResult{Allowed: result.Allowed, RetryAfter: result.RetryAfter}, nil
}

// BlacklistStore adapts auth-state cache invalidation to the OAuth service port.
type BlacklistStore struct {
	Store internalredis.Store
}

// DeleteAuthStates removes the cached auth-state entries for a revoked family.
func (s BlacklistStore) DeleteAuthStates(ctx context.Context, jtis []string) error {
	return s.Store.DeleteAuthStates(ctx, jtis)
}

// AuthorizeRequestStore persists validated authorize requests awaiting consent.
type AuthorizeRequestStore struct {
	Store internalredis.Store
}

// SaveAuthorizeRequest stashes a request under a fresh request ID.
//
// SetOneTime's SET NX semantics matter here: request IDs are random, so a
// collision means either a repeat of an in-flight ID or an attempt to overwrite
// somebody else's pending request. Refusing rather than overwriting keeps one ID
// bound to one set of authorization parameters.
func (s AuthorizeRequestStore) SaveAuthorizeRequest(
	ctx context.Context,
	requestID string,
	payload oauth.AuthorizeRequestPayload,
	ttl time.Duration,
) error {
	return s.Store.SetOneTime(ctx, s.Store.Keys.AuthorizeRequest(requestID), payload, ttl)
}

// PeekAuthorizeRequest reads a stashed request without consuming it and reports
// its remaining lifetime, so the consent page can display verified client
// metadata before the user decides. A missing or already-expired key is reported
// as not-found rather than an error.
func (s AuthorizeRequestStore) PeekAuthorizeRequest(
	ctx context.Context,
	requestID string,
) (oauth.AuthorizeRequestPayload, time.Duration, bool, error) {
	var payload oauth.AuthorizeRequestPayload
	if err := s.Store.PeekOneTime(ctx, s.Store.Keys.AuthorizeRequest(requestID), &payload); err != nil {
		if errors.Is(err, internalredis.ErrMiss) {
			return oauth.AuthorizeRequestPayload{}, 0, false, nil
		}
		return oauth.AuthorizeRequestPayload{}, 0, false, err
	}
	// PeekOneTime succeeded, so the key exists; guard the TTL edge where it
	// expired between the GET and the PTTL (PTTL returns a negative duration).
	ttl := s.Store.Client.PTTL(ctx, s.Store.Keys.AuthorizeRequest(requestID)).Val()
	if ttl <= 0 {
		return oauth.AuthorizeRequestPayload{}, 0, false, nil
	}
	return payload, ttl, true, nil
}

// ConsumeAuthorizeRequest atomically reads and deletes a stashed request.
//
// GetDel is what makes one authorize request yield at most one authorization
// code: two concurrent consent submissions race here and exactly one sees the
// payload. A missing key is reported as not-found rather than as an error, since
// an expired or already-spent request is an ordinary outcome the caller answers
// by asking the user to restart.
//
// The stash is keyed by request ID alone and is not bound to a user, because the
// first leg of the flow is unauthenticated by design — there is no subject to bind
// to when it is written. Anyone who learns a live request_id can therefore consume
// it and cancel that pending authorization. The consequence is bounded to denial of
// service on one in-flight request: the consumer's own consent would mint a code
// for their own subject, not the victim's. Containment rests on the ID being 16
// random bytes, the 10-minute TTL, and Referrer-Policy
// strict-origin-when-cross-origin keeping the query string out of cross-origin
// referrers. Binding a subject here would require authenticating leg one, which
// would break arriving from a third party with no Authorization header.
func (s AuthorizeRequestStore) ConsumeAuthorizeRequest(
	ctx context.Context,
	requestID string,
) (oauth.AuthorizeRequestPayload, bool, error) {
	var payload oauth.AuthorizeRequestPayload
	err := s.Store.GetDelOneTime(ctx, s.Store.Keys.AuthorizeRequest(requestID), &payload)
	if err != nil {
		if errors.Is(err, internalredis.ErrMiss) {
			return oauth.AuthorizeRequestPayload{}, false, nil
		}
		return oauth.AuthorizeRequestPayload{}, false, err
	}
	return payload, true, nil
}
