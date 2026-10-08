package sessionworker

import (
	"context"
	"errors"
	"testing"
	"time"

	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
)

type evictionQueue struct {
	items  []internalredis.DeviceEviction
	err    error
	acks   int
	ackErr error
	offset int
}

func (q *evictionQueue) PendingDeviceEvictions(_ context.Context, offset, _ int) ([]internalredis.DeviceEviction, error) {
	q.offset = offset
	return q.items, q.err
}
func (q *evictionQueue) AckDeviceEviction(context.Context, string) error { q.acks++; return q.ackErr }

type evictionResolver struct {
	resolved bool
	err      error
	calls    int
}

func (r *evictionResolver) ResolveDeviceEviction(context.Context, int64, string, string, string, time.Time, time.Time) (bool, error) {
	r.calls++
	return r.resolved, r.err
}
func TestDeviceEvictionAcknowledgesOnlyResolvedWork(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resolved bool
		err      error
		want     int
	}{{"pending proof", false, nil, 0}, {"database failure", false, errors.New("db down"), 0}, {"committed", true, nil, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			q := &evictionQueue{items: []internalredis.DeviceEviction{{Receipt: "receipt"}}}
			r := &evictionResolver{resolved: tc.resolved, err: tc.err}
			w := DeviceEvictions{Store: q, Tokens: r}
			w.process(context.Background(), 0)
			if q.acks != tc.want {
				t.Fatalf("acks=%d", q.acks)
			}
		})
	}
}
func TestDeviceEvictionPendingProofDoesNotStarveLaterPages(t *testing.T) {
	q := &evictionQueue{items: make([]internalredis.DeviceEviction, 100)}
	r := &evictionResolver{}
	w := DeviceEvictions{Store: q, Tokens: r}
	next := w.process(context.Background(), 0)
	if next != 100 || q.acks != 0 {
		t.Fatalf("offset=%d acks=%d", next, q.acks)
	}
	q.items = nil
	if next = w.process(context.Background(), next); next != 0 || q.offset != 100 {
		t.Fatalf("wrap offset=%d requested=%d", next, q.offset)
	}
}
func TestDeviceEvictionAckFailureReplaysCommittedWork(t *testing.T) {
	q := &evictionQueue{items: []internalredis.DeviceEviction{{Receipt: "receipt"}}, ackErr: errors.New("lost ack")}
	r := &evictionResolver{resolved: true}
	w := DeviceEvictions{Store: q, Tokens: r}
	w.process(context.Background(), 0)
	q.ackErr = nil
	w.process(context.Background(), 0)
	if r.calls != 2 || q.acks != 2 {
		t.Fatalf("resolve=%d ack=%d", r.calls, q.acks)
	}
}
