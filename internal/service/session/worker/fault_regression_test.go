package sessionworker

import (
	"context"
	"errors"
	"testing"
	"time"
)

type reviewBacklog struct {
	fakeOutbox
	remaining int64
	rounds    int
}

func (b *reviewBacklog) CleanupExpired(_ context.Context, _ time.Time, limit int) (int64, error) {
	b.rounds++
	n := min(int64(limit), b.remaining)
	b.remaining -= n
	return n, nil
}
func TestRegressionExpiredOutboxBacklog(t *testing.T) {
	b := &reviewBacklog{remaining: 500}
	w := TokenBlacklist{Outbox: b}
	w.cleanupExpired(context.Background())
	t.Logf("expired_start=500 deleted=%d remaining=%d cleanup_calls=%d default_interval=%s", 500-b.remaining, b.remaining, b.rounds, defaultTokenBlacklistCleanupRate)
	if b.remaining != 0 {
		t.Error("small expired backlog survives a cleanup cycle and will wait for the hourly ticker")
	}
}

func TestRegressionCleanupBoundedPassReschedulesBacklog(t *testing.T) {
	b := &reviewBacklog{remaining: 5000}
	w := TokenBlacklist{Outbox: b}
	next := w.cleanupExpired(context.Background())
	if b.rounds != 20 || b.remaining != 3000 || next != time.Second {
		t.Fatalf("rounds=%d remaining=%d next=%v", b.rounds, b.remaining, next)
	}
	for b.remaining > 0 {
		w.cleanupExpired(context.Background())
	}
}

type cleanupErrorOutbox struct {
	fakeOutbox
	calls int
}

func (b *cleanupErrorOutbox) CleanupExpired(ctx context.Context, _ time.Time, _ int) (int64, error) {
	b.calls++
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	return 0, errors.New("database unavailable")
}
func TestRegressionCleanupErrorAndCancellationStayBounded(t *testing.T) {
	b := &cleanupErrorOutbox{}
	w := TokenBlacklist{Outbox: b}
	if next := w.cleanupExpired(context.Background()); next != time.Second || b.calls != 1 {
		t.Fatalf("retry=%v calls=%d", next, b.calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.cleanupExpired(ctx)
	if b.calls != 2 {
		t.Fatalf("calls=%d", b.calls)
	}
}
