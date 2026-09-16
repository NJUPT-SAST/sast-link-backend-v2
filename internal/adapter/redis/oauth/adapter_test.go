package oauthredis

import (
	"context"
	"errors"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
)

// scriptedClient answers GET with a fixed payload and PTTL with a fixed
// outcome, so the adapter's two-call peek can be driven through the edges a
// live Redis cannot be asked to produce on demand. The embedded interface is
// left nil: these two commands are the whole of the peek path.
type scriptedClient struct {
	internalredis.Cmdable
	payload string
	ttl     time.Duration
	ttlErr  error
}

func (c scriptedClient) Get(_ context.Context, key string) *goredis.StringCmd {
	cmd := goredis.NewStringCmd(context.Background(), "get", key)
	cmd.SetVal(c.payload)
	return cmd
}

func (c scriptedClient) PTTL(_ context.Context, key string) *goredis.DurationCmd {
	cmd := goredis.NewDurationCmd(context.Background(), time.Millisecond, "pttl", key)
	cmd.SetVal(c.ttl)
	cmd.SetErr(c.ttlErr)
	return cmd
}

func peekStore(client internalredis.Cmdable) AuthorizeRequestStore {
	return AuthorizeRequestStore{Store: internalredis.Store{
		Client: client,
		Keys:   internalredis.NewKeys("sastlink:test"),
	}}
}

// A PTTL that fails must surface as a dependency fault. DurationCmd.Val()
// reports the zero duration on a failed command, so reading it that way turns
// a Redis error into "expired between the GET and the PTTL" and answers 400,
// sending the user to restart a flow that is still valid.
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

// The edge the guard exists for: the key can expire between the GET and the
// PTTL. That is an ordinary not-found, not an error.
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
