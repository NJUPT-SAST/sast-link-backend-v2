package adminuser

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

type reviewConcurrentRepo struct {
	*fakeUsers
	entered chan struct{}
	release chan struct{}
	active  atomic.Int32
	peak    atomic.Int32
}

func (r *reviewConcurrentRepo) UpdateAdminUser(_ context.Context, _ int64, _ repository.AdminUserUpdate, _ model.UserRole, _ time.Time) ([]model.BlacklistEntry, bool, error) {
	n := r.active.Add(1)
	defer r.active.Add(-1)
	for {
		old := r.peak.Load()
		if n <= old || r.peak.CompareAndSwap(old, n) {
			break
		}
	}
	r.entered <- struct{}{}
	<-r.release
	return nil, false, nil
}
func TestRegressionBatchFanoutBounded(t *testing.T) {
	h := newHarness(t)
	h.users.findResult = targetUser(model.UserRoleFreshman, model.UserStateNJUPTer)
	repo := &reviewConcurrentRepo{fakeUsers: h.users, entered: make(chan struct{}, 16), release: make(chan struct{})}
	h.service.Users = repo
	h.service.Audit = nil
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			_, err := h.service.BatchUpdateUsers(context.Background(), BatchUpdateUsersInput{IDs: makeIDs(8), Role: "member", AdminUserID: testAdminID, AdminRole: "admin"})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	timeout := time.NewTimer(100 * time.Millisecond)
	defer timeout.Stop()
loop:
	for range 16 {
		select {
		case <-repo.entered:
		case <-timeout.C:
			break loop
		}
	}
	close(repo.release)
	wg.Wait()
	t.Logf("concurrent_batches=2 max_inflight_UpdateAdminUser=%d (repository barrier fixture; not PostgreSQL throughput)", repo.peak.Load())
	if repo.peak.Load() != 1 {
		t.Fatalf("process-wide batch concurrency=%d, want 1", repo.peak.Load())
	}
}

func TestRegressionBatchCanceledWhileQueued(t *testing.T) {
	batchUpdateGate <- struct{}{}
	defer func() { <-batchUpdateGate }()
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() {
		_, err := h.service.BatchUpdateUsers(ctx, BatchUpdateUsersInput{IDs: makeIDs(8), Role: "member", AdminUserID: testAdminID, AdminRole: "admin"})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled batch succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled batch waited for gate")
	}
	if h.users.updateCalls != 0 {
		t.Fatal("canceled queued batch wrote users")
	}
}
