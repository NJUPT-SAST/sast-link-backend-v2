package worker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }

type deleteCall struct {
	table     string
	cutoff    time.Time
	batchSize int
}

// fakeRetentionStore is mutex-guarded because Run sweeps on its own goroutine
// while the test observes progress from another.
type fakeRetentionStore struct {
	mu          sync.Mutex
	locked      bool
	lockResult  bool
	lockErr     error
	unlockCalls int
	calls       []deleteCall
	// remaining counts rows still due per table, so a store can force the worker
	// through more than one batch.
	remaining map[string]int64
	failOn    string
	// recomputeRowsLeft budgets the derived-state sweep; recomputeCalls counts
	// how many passes ran; recomputeErr fails one pass.
	recomputeRowsLeft int64
	recomputeCalls    int
	recomputeErr      error
	// recomputeCursors records the cursor each pass was handed, so a test can
	// assert the sweep advances instead of re-reading the same head.
	recomputeCursors []int64
}

func newFakeRetentionStore() *fakeRetentionStore {
	return &fakeRetentionStore{lockResult: true, remaining: map[string]int64{}}
}

func (s *fakeRetentionStore) TryLock(context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockErr != nil {
		return false, s.lockErr
	}
	s.locked = s.lockResult
	return s.lockResult, nil
}

func (s *fakeRetentionStore) Unlock(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unlockCalls++
	s.locked = false
	return nil
}

func (s *fakeRetentionStore) del(table string, cutoff time.Time, batchSize int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, deleteCall{table: table, cutoff: cutoff, batchSize: batchSize})
	if s.failOn == table {
		return 0, errors.New("delete failed")
	}
	left := s.remaining[table]
	if left <= 0 {
		return 0, nil
	}
	removed := int64(batchSize)
	if left < removed {
		removed = left
	}
	s.remaining[table] = left - removed
	return removed, nil
}

// snapshot copies the recorded calls so assertions never read the slice the
// worker goroutine may still be appending to.
func (s *fakeRetentionStore) snapshot() []deleteCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]deleteCall(nil), s.calls...)
}

func (s *fakeRetentionStore) callsFor(table string) int {
	var count int
	for _, call := range s.snapshot() {
		if call.table == table {
			count++
		}
	}
	return count
}

func (s *fakeRetentionStore) remainingFor(table string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.remaining[table]
}

func (s *fakeRetentionStore) recomputeSnapshot() (calls int, cursors []int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recomputeCalls, append([]int64(nil), s.recomputeCursors...)
}

func (s *fakeRetentionStore) unlocks() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unlockCalls
}

func (s *fakeRetentionStore) isLocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.locked
}

func (s *fakeRetentionStore) DeleteExpiredAuthorizations(_ context.Context, cutoff time.Time, batchSize int) (int64, error) {
	return s.del("oauth_authorizations", cutoff, batchSize)
}

func (s *fakeRetentionStore) DeleteExpiredAccessTokens(_ context.Context, cutoff time.Time, batchSize int) (int64, error) {
	return s.del("oauth_access_tokens", cutoff, batchSize)
}

func (s *fakeRetentionStore) DeleteRevokedRefreshTokens(_ context.Context, cutoff time.Time, batchSize int) (int64, error) {
	return s.del("oauth_refresh_tokens", cutoff, batchSize)
}

func (s *fakeRetentionStore) DeleteExpiredAuditLogs(_ context.Context, cutoff time.Time, batchSize int) (int64, error) {
	return s.del("audit_logs", cutoff, batchSize)
}

func (s *fakeRetentionStore) DeleteExpiredAlumniRequests(_ context.Context, cutoff time.Time, batchSize int) (int64, error) {
	return s.del("alumni_requests", cutoff, batchSize)
}

func (s *fakeRetentionStore) RecomputeDerivedState(_ context.Context, cursor int64, _ time.Time, batchSize int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recomputeCalls++
	s.recomputeCursors = append(s.recomputeCursors, cursor)
	if s.recomputeErr != nil {
		return 0, s.recomputeErr
	}
	if s.recomputeRowsLeft <= 0 {
		return 0, nil
	}
	// Hand out batches of batchSize rows until the fake's budget is spent; a
	// short final batch is reported as "swept" via 0, like the real store.
	next := cursor + int64(batchSize)
	s.recomputeRowsLeft -= int64(batchSize)
	if s.recomputeRowsLeft <= 0 {
		return 0, nil
	}
	return next, nil
}

func testRetention(store RetentionStore, now time.Time) Retention {
	return Retention{
		Store:            store,
		Interval:         time.Hour,
		BatchSize:        10,
		AuthorizationAge: time.Hour,
		AccessTokenAge:   24 * time.Hour,
		RefreshTokenAge:  48 * time.Hour,
		AuditLogAge:      90 * 24 * time.Hour,
		AlumniRequestAge: 180 * 24 * time.Hour,
		Clock:            fixedClock{value: now},
	}
}

// Each table gets its own cutoff, derived from its own window. A single shared
// cutoff would apply the audit window to authorization codes or vice versa.
func TestRetentionSweepUsesPerTableCutoffs(t *testing.T) {
	now := time.Now().UTC()
	store := newFakeRetentionStore()
	testRetention(store, now).sweep(context.Background())

	want := map[string]time.Time{
		"oauth_authorizations": now.Add(-time.Hour),
		"oauth_access_tokens":  now.Add(-24 * time.Hour),
		"oauth_refresh_tokens": now.Add(-48 * time.Hour),
		"audit_logs":           now.Add(-90 * 24 * time.Hour),
		"alumni_requests":      now.Add(-180 * 24 * time.Hour),
	}
	calls := store.snapshot()
	if len(calls) != len(want) {
		t.Fatalf("delete calls = %d, want %d", len(calls), len(want))
	}
	for _, call := range calls {
		expected, ok := want[call.table]
		if !ok {
			t.Fatalf("unexpected table %q", call.table)
		}
		if !call.cutoff.Equal(expected) {
			t.Errorf("%s cutoff = %s, want %s", call.table, call.cutoff, expected)
		}
		if call.batchSize != 10 {
			t.Errorf("%s batch size = %d, want 10", call.table, call.batchSize)
		}
	}
}

// Losing the advisory lock means another instance is already sweeping the same
// rows, so this tick must do nothing rather than duplicate the scan.
func TestRetentionSweepSkipsWithoutLock(t *testing.T) {
	store := newFakeRetentionStore()
	store.lockResult = false
	testRetention(store, time.Now().UTC()).sweep(context.Background())

	if got := len(store.snapshot()); got != 0 {
		t.Fatalf("delete calls = %d, want 0 when the lock is held elsewhere", got)
	}
	if got := store.unlocks(); got != 0 {
		t.Fatalf("unlock calls = %d, want 0 for a lock never acquired", got)
	}
}

// A lock left held would block every later sweep on every instance, since it is
// session-scoped and outlives the failed pass.
func TestRetentionSweepReleasesLockAfterDeleteFailure(t *testing.T) {
	store := newFakeRetentionStore()
	store.failOn = "oauth_access_tokens"
	testRetention(store, time.Now().UTC()).sweep(context.Background())

	if got := store.unlocks(); got != 1 {
		t.Fatalf("unlock calls = %d, want 1", got)
	}
	if store.isLocked() {
		t.Fatal("lock still held after sweep")
	}
}

// A failing table must not abort the tables after it: they are independent.
func TestRetentionSweepContinuesPastFailingTable(t *testing.T) {
	store := newFakeRetentionStore()
	store.failOn = "oauth_authorizations"
	testRetention(store, time.Now().UTC()).sweep(context.Background())

	seen := map[string]bool{}
	for _, call := range store.snapshot() {
		seen[call.table] = true
	}
	for _, table := range []string{"oauth_access_tokens", "oauth_refresh_tokens", "audit_logs"} {
		if !seen[table] {
			t.Errorf("table %q not swept after an earlier table failed", table)
		}
	}
}

// A full batch means more rows may qualify, so the worker keeps going until a pass
// comes back short. Otherwise one tick would only ever remove BatchSize rows and a
// backlog could outpace the schedule forever.
func TestRetentionDrainsUntilPassComesBackShort(t *testing.T) {
	store := newFakeRetentionStore()
	store.remaining["audit_logs"] = 25
	testRetention(store, time.Now().UTC()).sweep(context.Background())

	// 10 + 10 + 5: the third pass is short and stops the loop.
	if got := store.callsFor("audit_logs"); got != 3 {
		t.Fatalf("audit_logs delete calls = %d, want 3", got)
	}
	if got := store.remainingFor("audit_logs"); got != 0 {
		t.Fatalf("audit_logs remaining = %d, want 0", got)
	}
}

// An enormous backlog must not monopolize the connection pool for one tick.
func TestRetentionDrainStopsAtPassCap(t *testing.T) {
	store := newFakeRetentionStore()
	store.remaining["audit_logs"] = 10_000
	testRetention(store, time.Now().UTC()).sweep(context.Background())

	if got := store.callsFor("audit_logs"); got != maxRetentionPasses {
		t.Fatalf("audit_logs delete calls = %d, want the %d-pass cap", got, maxRetentionPasses)
	}
}

func TestRetentionRunRejectsInvalidConfig(t *testing.T) {
	for _, test := range []struct {
		name   string
		worker Retention
	}{
		{name: "no store", worker: Retention{AuthorizationAge: time.Hour, AccessTokenAge: time.Hour, RefreshTokenAge: time.Hour, AuditLogAge: time.Hour}},
		{name: "zero window", worker: Retention{Store: newFakeRetentionStore(), AuthorizationAge: time.Hour, AccessTokenAge: time.Hour, RefreshTokenAge: time.Hour}},
		{name: "negative batch size", worker: Retention{Store: newFakeRetentionStore(), AuthorizationAge: time.Hour, AccessTokenAge: time.Hour, RefreshTokenAge: time.Hour, AuditLogAge: time.Hour, BatchSize: -1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.worker.Run(context.Background()); err == nil {
				t.Fatal("Run() error = nil, want validation failure")
			}
		})
	}
}

// Run sweeps once before waiting for the first tick, so a restart does not leave a
// backlog sitting for a whole interval.
func TestRetentionRunSweepsBeforeFirstTick(t *testing.T) {
	store := newFakeRetentionStore()
	ctx, cancel := context.WithCancel(context.Background())
	worker := testRetention(store, time.Now().UTC())

	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()

	deadline := time.After(2 * time.Second)
	for len(store.snapshot()) == 0 {
		select {
		case <-deadline:
			cancel()
			t.Fatal("Run() did not sweep before the first tick")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v, want nil after cancel", err)
	}
}

// The derived-state pass advances by cursor instead of re-reading the same head
// of the table: an unchanged row stays a candidate, so a sweep that restarts its
// scan every pass would never reach the tail.
func TestRetentionDerivedStateAdvancesByCursor(t *testing.T) {
	store := newFakeRetentionStore()
	store.recomputeRowsLeft = 25
	testRetention(store, time.Now().UTC()).sweep(context.Background())

	calls, cursors := store.recomputeSnapshot()
	if calls != 3 {
		t.Fatalf("recompute calls = %d, want 3 passes over 25 rows at batch size 10", calls)
	}
	want := []int64{0, 10, 20}
	for i, expected := range want {
		if cursors[i] != expected {
			t.Fatalf("pass %d cursor = %d, want %d", i, cursors[i], expected)
		}
	}
}

// Sweeping to the end resets the carried cursor, so the next tick re-checks
// every row against the academic-year rule instead of trusting the last pass.
func TestRetentionDerivedStateResetsCursorAfterFullSweep(t *testing.T) {
	store := newFakeRetentionStore()
	store.recomputeRowsLeft = 5
	cursor := int64(7)
	w := testRetention(store, time.Now().UTC())
	w.DerivedStateCursor = &cursor
	w.sweep(context.Background())

	if cursor != 0 {
		t.Fatalf("carried cursor = %d, want 0 after a sweep that reached the end", cursor)
	}
}

// A table larger than one tick's budget must not have its tail starved forever:
// the position is carried so the next tick continues where this one stopped.
func TestRetentionDerivedStateCarriesCursorAtPassCap(t *testing.T) {
	store := newFakeRetentionStore()
	store.recomputeRowsLeft = int64(maxRetentionPasses*10) + 100
	cursor := int64(0)
	w := testRetention(store, time.Now().UTC())
	w.DerivedStateCursor = &cursor
	w.sweep(context.Background())

	calls, _ := store.recomputeSnapshot()
	if calls != maxRetentionPasses {
		t.Fatalf("recompute calls = %d, want the pass cap %d", calls, maxRetentionPasses)
	}
	if cursor != int64(maxRetentionPasses*10) {
		t.Fatalf("carried cursor = %d, want %d so the next tick resumes instead of restarting",
			cursor, int64(maxRetentionPasses*10))
	}

	// Second tick: resumes from the carried position rather than re-reading the head.
	resumedFrom := cursor
	store.recomputeRowsLeft = 5
	w.sweep(context.Background())
	_, cursors := store.recomputeSnapshot()
	if first := cursors[len(cursors)-1]; first != resumedFrom {
		t.Fatalf("next tick started at cursor %d, want the carried %d", first, resumedFrom)
	}
}

// A failed derived-state pass is logged and abandoned until the next tick, like a
// failed delete: it must not take the API process down and must not spin.
func TestRetentionDerivedStateFailureStopsPasses(t *testing.T) {
	store := newFakeRetentionStore()
	store.recomputeRowsLeft = 1000
	store.recomputeErr = errors.New("recompute failed")
	testRetention(store, time.Now().UTC()).sweep(context.Background())

	calls, _ := store.recomputeSnapshot()
	if calls != 1 {
		t.Fatalf("recompute calls = %d, want 1: the error must end the loop, not retry it", calls)
	}
	// The lock is still released for the next tick to re-acquire.
	if got := store.unlocks(); got != 1 {
		t.Fatalf("unlock calls = %d, want 1 after a failed pass", got)
	}
}

// Losing the advisory lock means another instance owns the sweep, so no
// derived-state pass may run either: two instances writing state concurrently
// would duplicate work the winner is already doing.
func TestRetentionDerivedStateSkippedWithoutLock(t *testing.T) {
	store := newFakeRetentionStore()
	store.lockResult = false
	store.recomputeRowsLeft = 100
	testRetention(store, time.Now().UTC()).sweep(context.Background())

	if calls, _ := store.recomputeSnapshot(); calls != 0 {
		t.Fatalf("recompute calls = %d, want 0 when the lock is held elsewhere", calls)
	}
}
