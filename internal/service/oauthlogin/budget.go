package oauthlogin

import (
	"context"
	"time"
)

// RequestBudget leaves response-writing headroom beneath the server's 10s
// WriteTimeout. Handlers install it before decoding; services also install it
// for non-HTTP callers. All detached work retains this absolute deadline.
const RequestBudget = 8 * time.Second
const callbackExchangeBudget = 5 * time.Second

type requestDeadlineKey struct{}

func WithRequestBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Value(requestDeadlineKey{}).(time.Time)
	if !ok {
		deadline = time.Now().Add(RequestBudget)
	}
	if d, has := ctx.Deadline(); has && d.Before(deadline) {
		deadline = d
	}
	ctx = context.WithValue(ctx, requestDeadlineKey{}, deadline)
	return context.WithDeadline(ctx, deadline)
}

// workBudget reserves the final second for recovery/audit and HTTP response.
func workBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline := ctx.Value(requestDeadlineKey{}).(time.Time)
	return context.WithDeadline(ctx, deadline.Add(-time.Second))
}

func cleanupBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(500 * time.Millisecond)
	if d, ok := ctx.Value(requestDeadlineKey{}).(time.Time); ok && d.Before(deadline) {
		deadline = d
	}
	return context.WithDeadline(context.WithoutCancel(ctx), deadline)
}
