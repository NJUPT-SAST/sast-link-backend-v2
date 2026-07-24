package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

type fakeOutbox struct {
	claimed    []model.TokenBlacklistOutbox
	claimCalls int
	acks       []int64
	failures   []fakeFailure
	cleanups   int
	claimErr   error
	claimCall  func()
	ackCall    func()
}

type fakeFailure struct {
	id              int64
	attemptedAt     time.Time
	nextDeliveryAt  time.Time
	deliveryMessage string
}

func (f *fakeOutbox) ClaimDue(_ context.Context, _ time.Time, _ time.Duration, _ int) ([]model.TokenBlacklistOutbox, error) {
	f.claimCalls++
	if f.claimCall != nil {
		f.claimCall()
	}
	if f.claimErr != nil {
		return nil, f.claimErr
	}
	entries := f.claimed
	f.claimed = nil
	return entries, nil
}

func (f *fakeOutbox) Ack(_ context.Context, id int64, _ string) (bool, error) {
	f.acks = append(f.acks, id)
	if f.ackCall != nil {
		f.ackCall()
	}
	return true, nil
}

func (f *fakeOutbox) Fail(_ context.Context, id int64, _ string, attemptedAt, nextDeliveryAt time.Time, deliveryError string) (bool, error) {
	f.failures = append(f.failures, fakeFailure{id: id, attemptedAt: attemptedAt, nextDeliveryAt: nextDeliveryAt, deliveryMessage: deliveryError})
	if f.ackCall != nil {
		f.ackCall()
	}
	return true, nil
}

func (f *fakeOutbox) CleanupExpired(_ context.Context, _ time.Time) (int64, error) {
	f.cleanups++
	return 0, nil
}

type fakeBlacklist struct {
	jti string
	ttl time.Duration
	err error
}

func (f *fakeBlacklist) BlacklistJTI(_ context.Context, jti string, ttl time.Duration) error {
	f.jti = jti
	f.ttl = ttl
	return f.err
}

func TestTokenBlacklistRunDeliversAndAcknowledges(t *testing.T) {
	now := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC)
	claim := "claim"
	outbox := &fakeOutbox{claimed: []model.TokenBlacklistOutbox{{ID: 1, TokenID: "jti", ExpiresAt: now.Add(time.Minute), ClaimToken: &claim}}}
	ctx, cancel := context.WithCancel(context.Background())
	outbox.ackCall = cancel
	blacklist := &fakeBlacklist{}
	worker := TokenBlacklist{Outbox: outbox, Blacklist: blacklist, Interval: time.Hour, CleanupInterval: time.Hour, Now: func() time.Time { return now }}

	if err := worker.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if blacklist.jti != "jti" || blacklist.ttl != time.Minute {
		t.Fatalf("blacklist = (%q, %s), want jti/1m", blacklist.jti, blacklist.ttl)
	}
	if len(outbox.acks) != 1 || outbox.acks[0] != 1 || len(outbox.failures) != 0 {
		t.Fatalf("acks=%v failures=%v", outbox.acks, outbox.failures)
	}
	if outbox.cleanups != 1 {
		t.Fatalf("cleanups = %d, want 1", outbox.cleanups)
	}
}

func TestTokenBlacklistRunSchedulesFailedDelivery(t *testing.T) {
	now := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC)
	claim := "claim"
	ctx, cancel := context.WithCancel(context.Background())
	outbox := &fakeOutbox{claimed: []model.TokenBlacklistOutbox{{ID: 2, TokenID: "jti", ExpiresAt: now.Add(time.Minute), AttemptCount: 2, ClaimToken: &claim}}, ackCall: cancel}
	blacklist := &fakeBlacklist{err: errors.New("redis down")}
	worker := TokenBlacklist{Outbox: outbox, Blacklist: blacklist, Interval: time.Hour, CleanupInterval: time.Hour, Now: func() time.Time { return now }}

	if err := worker.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(outbox.acks) != 0 || len(outbox.failures) != 1 {
		t.Fatalf("acks=%v failures=%v", outbox.acks, outbox.failures)
	}
	failure := outbox.failures[0]
	if failure.id != 2 || failure.nextDeliveryAt.Sub(failure.attemptedAt) != 4*time.Second || failure.deliveryMessage != "redis down" {
		t.Fatalf("failure = %+v", failure)
	}
}

func TestTokenBlacklistRunAcknowledgesNaturallyExpiredDelivery(t *testing.T) {
	now := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC)
	claim := "claim"
	ctx, cancel := context.WithCancel(context.Background())
	outbox := &fakeOutbox{claimed: []model.TokenBlacklistOutbox{{ID: 3, TokenID: "jti", ExpiresAt: now, ClaimToken: &claim}}, ackCall: cancel}
	worker := TokenBlacklist{Outbox: outbox, Blacklist: &fakeBlacklist{}, Interval: time.Hour, CleanupInterval: time.Hour, Now: func() time.Time { return now }}

	if err := worker.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(outbox.acks) != 1 || outbox.acks[0] != 3 {
		t.Fatalf("acks = %v, want [3]", outbox.acks)
	}
}

func TestTokenBlacklistRunRetriesClaimErrorsUntilCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	outbox := &fakeOutbox{claimErr: errors.New("database down")}
	outbox.claimCall = func() {
		if outbox.claimCalls >= 2 {
			cancel()
		}
	}
	worker := TokenBlacklist{Outbox: outbox, Blacklist: &fakeBlacklist{}, Interval: time.Millisecond, CleanupInterval: time.Hour}

	if err := worker.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if outbox.claimCalls < 2 {
		t.Fatalf("claim calls = %d, want at least 2", outbox.claimCalls)
	}
}

func TestTokenBlacklistRunRejectsInvalidDependencies(t *testing.T) {
	if err := (TokenBlacklist{}).Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want invalid dependencies error")
	}
}
