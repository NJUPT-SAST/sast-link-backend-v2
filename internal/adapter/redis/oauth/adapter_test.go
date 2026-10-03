package oauthredis

import (
	"context"
	"errors"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
)

// scriptedClient answers the peek's single EVAL with a fixed {value, ttl}
// pair (or an error), so the atomic read can be driven through the edges a
// live Redis cannot be asked to produce on demand. The embedded interface is
// left nil: this one command is the whole of the peek path.
type scriptedClient struct {
	internalredis.Cmdable
	payload string
	ttl     time.Duration
	ttlErr  error
}

// EvalSha answers NOSCRIPT so evalScript falls back to the scripted Eval: the
// fake has no script cache to prime.
func (c scriptedClient) EvalSha(_ context.Context, _ string, _ []string, _ ...any) *goredis.Cmd {
	cmd := goredis.NewCmd(context.Background(), "evalsha")
	cmd.SetErr(errors.New("NOSCRIPT No cached script surface"))
	return cmd
}

func (c scriptedClient) Eval(_ context.Context, _ string, _ []string, _ ...any) *goredis.Cmd {
	cmd := goredis.NewCmd(context.Background(), "eval")
	if c.ttlErr != nil {
		cmd.SetErr(c.ttlErr)
		return cmd
	}
	cmd.SetVal([]any{c.payload, c.ttl.Milliseconds()})
	return cmd
}

func peekStore(client internalredis.Cmdable) AuthorizeRequestStore {
	return AuthorizeRequestStore{Store: internalredis.Store{
		Client: client,
		Keys:   internalredis.NewKeys("sastlink:test"),
	}}
}

// An EVAL that fails must surface as a dependency fault rather than as an
// ordinary not-found: the caller answers a not-found by telling the user to
// restart a flow that may still be perfectly valid.
func TestPeekAuthorizeRequestReportsTTLFailure(t *testing.T) {
	boom := errors.New("redis down")
	store := peekStore(scriptedClient{
		payload: `{"client_id":"sast-link-web"}`,
		ttlErr:  boom,
	})

	_, _, found, err := store.PeekAuthorizeRequest(context.Background(), "req_1")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the PTTL failure", err)
	}
	if found {
		t.Fatal("found = true alongside the error, want false")
	}
}

// A key past its TTL reads as an ordinary not-found, not an error: the atomic
// {value, PTTL} pair makes "expired" indistinguishable from a slightly earlier
// miss, which is exactly the semantics the caller wants.
func TestPeekAuthorizeRequestReportsExpiredKeyAsNotFound(t *testing.T) {
	store := peekStore(scriptedClient{
		payload: `{"client_id":"sast-link-web"}`,
		ttl:     time.Duration(-2),
	})

	_, _, found, err := store.PeekAuthorizeRequest(context.Background(), "req_1")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if found {
		t.Fatal("found = true, want false for an expired key")
	}
}

// A live key reports its payload and remaining lifetime.
func TestPeekAuthorizeRequestReportsLiveKey(t *testing.T) {
	store := peekStore(scriptedClient{
		payload: `{"client_id":"sast-link-web","scopes":["openid"]}`,
		ttl:     10 * time.Minute,
	})

	payload, ttl, found, err := store.PeekAuthorizeRequest(context.Background(), "req_1")
	if err != nil || !found {
		t.Fatalf("found = %v, err = %v, want a live key", found, err)
	}
	if payload.ClientID != "sast-link-web" {
		t.Fatalf("client_id = %q, want sast-link-web", payload.ClientID)
	}
	if ttl != 10*time.Minute {
		t.Fatalf("ttl = %v, want 10m", ttl)
	}
}
