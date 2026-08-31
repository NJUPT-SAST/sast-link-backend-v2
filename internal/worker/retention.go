// Package worker runs scheduled maintenance that is not tied to a single service.
package worker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/shared"
)

const (
	defaultRetentionInterval  = time.Hour
	defaultRetentionBatchSize = 1000
	// maxRetentionPasses bounds one tick. A table that has gone uncleaned for
	// months would otherwise be swept to empty in a single tick, holding a share of
	// the connection pool that live traffic needs. Whatever is left over is picked
	// up next tick, so the backlog still drains, just spread out.
	maxRetentionPasses = 20
)

// RetentionStore deletes rows past their retention window, in batches.
//
// Each Delete* method returns the number of rows removed so the worker can keep
// sweeping until a pass comes back short.
type RetentionStore interface {
	TryLock(ctx context.Context) (bool, error)
	Unlock(ctx context.Context) error
	DeleteExpiredAuthorizations(ctx context.Context, cutoff time.Time, batchSize int) (int64, error)
	DeleteExpiredAccessTokens(ctx context.Context, cutoff time.Time, batchSize int) (int64, error)
	DeleteRevokedRefreshTokens(ctx context.Context, cutoff time.Time, batchSize int) (int64, error)
	DeleteExpiredAuditLogs(ctx context.Context, cutoff time.Time, batchSize int) (int64, error)
	// DeleteExpiredAlumniRequests removes tickets reviewed before cutoff. Only
	// approved and rejected ones: a pending ticket is never swept, however old,
	// because the handling target is a statement in the UI rather than a rule the
	// backend enforces, and deleting an unreviewed application would lose someone's
	// request instead of expiring it.
	DeleteExpiredAlumniRequests(ctx context.Context, cutoff time.Time, batchSize int) (int64, error)
	// RecomputeDerivedState recalibrates user.state against the derivation rule
	// (internal/validate) for unpinned live accounts, in id order past cursor.
	// The rule lives in Go, so this is the batch job that keeps stored states
	// current as the academic year advances; it never revokes sessions.
	// Returns the next cursor (0 = swept to the end).
	RecomputeDerivedState(ctx context.Context, cursor int64, now time.Time, batchSize int) (int64, error)
}

// Retention deletes expired OAuth metadata and aged-out audit logs.
//
// Scheduling lives here rather than in pg_cron because the production database has
// no pg_cron extension and loading one needs shared_preload_libraries plus a
// restart. Keeping it in Go also keeps the retention rules under test: the
// Testcontainers suite runs postgres:16-alpine, which cannot load pg_cron at all,
// so a pg_cron implementation would ship untested.
type Retention struct {
	Store            RetentionStore
	Interval         time.Duration
	BatchSize        int
	AuthorizationAge time.Duration
	AccessTokenAge   time.Duration
	RefreshTokenAge  time.Duration
	AuditLogAge      time.Duration
	// AlumniRequestAge is measured from reviewed_at, not created_at: the clock on a
	// ticket's retention starts when it was decided, and an unreviewed one has no
	// start.
	AlumniRequestAge time.Duration
	Clock            auth.Clock
}

// Run sweeps on a ticker until ctx is canceled.
func (w Retention) Run(ctx context.Context) error {
	if err := w.validate(); err != nil {
		return err
	}
	ticker := time.NewTicker(shared.DurationOrDefault(w.Interval, defaultRetentionInterval))
	defer ticker.Stop()

	w.sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w.sweep(ctx)
		}
	}
}

// sweep runs one retention pass over every target, holding the advisory lock.
//
// Failures are logged and abandoned until the next tick rather than returned:
// retention falling behind degrades storage, while returning an error from Run
// would take the whole API process down with it.
func (w Retention) sweep(ctx context.Context) {
	acquired, err := w.Store.TryLock(ctx)
	if err != nil {
		if ctx.Err() == nil {
			slog.Error("acquire retention lock", "error", err)
		}
		return
	}
	if !acquired {
		// Another instance is sweeping the same rows. Skipping is correct: the next
		// tick covers anything the winner leaves behind.
		return
	}
	defer func() {
		// Detached from ctx on purpose: the lock is session-scoped, and an unlock
		// skipped during shutdown would leave it held until the pooled connection is
		// recycled, blocking every later sweep on every instance.
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if unlockErr := w.Store.Unlock(unlockCtx); unlockErr != nil {
			slog.Error("release retention lock", "error", unlockErr)
		}
	}()

	now := w.now()
	for _, target := range []struct {
		name   string
		age    time.Duration
		delete func(context.Context, time.Time, int) (int64, error)
	}{
		{"oauth_authorizations", w.AuthorizationAge, w.Store.DeleteExpiredAuthorizations},
		{"oauth_access_tokens", w.AccessTokenAge, w.Store.DeleteExpiredAccessTokens},
		{"oauth_refresh_tokens", w.RefreshTokenAge, w.Store.DeleteRevokedRefreshTokens},
		{"audit_logs", w.AuditLogAge, w.Store.DeleteExpiredAuditLogs},
		{"alumni_requests", w.AlumniRequestAge, w.Store.DeleteExpiredAlumniRequests},
	} {
		if ctx.Err() != nil {
			return
		}
		w.drain(ctx, target.name, now.Add(-target.age), target.delete)
	}
	// Derived user state is recalibrated in the same sweep, under the same
	// advisory lock, so two instances cannot interleave state writes. Unlike the
	// deletes above, an unchanged row still matches the candidate predicate, so
	// the cursor advances by id and a short batch ends the loop.
	var cursor int64
	for pass := 0; pass < maxRetentionPasses; pass++ {
		if ctx.Err() != nil {
			return
		}
		next, recErr := w.Store.RecomputeDerivedState(ctx, cursor, now, w.batchSize())
		if recErr != nil {
			if ctx.Err() == nil {
				slog.Error("retention sweep derived state", "error", recErr)
			}
			return
		}
		if next == 0 {
			return
		}
		cursor = next
	}
	// Hitting the pass cap means the table outgrew one tick's budget. Say so,
	// rather than letting a permanent backlog look like a clean sweep.
	slog.Warn("retention derived-state sweep truncated at pass cap",
		"cursor", cursor, "passes", maxRetentionPasses)
}

// drain deletes in batches until a pass comes back short or the pass cap is hit.
func (w Retention) drain(
	ctx context.Context,
	table string,
	cutoff time.Time,
	remove func(context.Context, time.Time, int) (int64, error),
) {
	batchSize := w.batchSize()
	var total int64
	for pass := 0; pass < maxRetentionPasses; pass++ {
		if ctx.Err() != nil {
			return
		}
		removed, err := remove(ctx, cutoff, batchSize)
		if err != nil {
			if ctx.Err() == nil {
				slog.Error("retention sweep", "table", table, "deleted", total, "error", err)
			}
			return
		}
		total += removed
		if removed < int64(batchSize) {
			if total > 0 {
				slog.Info("retention sweep", "table", table, "deleted", total, "cutoff", cutoff)
			}
			return
		}
	}
	// Hitting the cap means rows still qualify. Say so, rather than letting a
	// permanent backlog look like a clean sweep.
	slog.Warn("retention sweep truncated at pass cap",
		"table", table, "deleted", total, "cutoff", cutoff, "passes", maxRetentionPasses)
}

func (w Retention) validate() error {
	if w.Store == nil {
		return fmt.Errorf("retention worker requires a store")
	}
	if w.AuthorizationAge <= 0 || w.AccessTokenAge <= 0 || w.RefreshTokenAge <= 0 ||
		w.AuditLogAge <= 0 || w.AlumniRequestAge <= 0 {
		return fmt.Errorf("retention worker requires positive retention windows")
	}
	if w.Interval < 0 || w.BatchSize < 0 {
		return fmt.Errorf("retention worker interval and batch size must not be negative")
	}
	return nil
}

func (w Retention) batchSize() int {
	if w.BatchSize > 0 {
		return w.BatchSize
	}
	return defaultRetentionBatchSize
}

func (w Retention) now() time.Time {
	clock := w.Clock
	if clock == nil {
		clock = auth.SystemClock
	}
	return clock.Now().UTC()
}
