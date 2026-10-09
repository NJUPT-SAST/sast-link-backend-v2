// Package worker runs scheduled maintenance that is not tied to a single service.
package worker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/objectstore"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
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
	// maxDerivedStateFailures is the consecutive-tick threshold that resets the
	// derived-state cursor to the table head; see Retention.derivedFailures.
	maxDerivedStateFailures = 3
)

// RetentionStore runs the periodic maintenance the service needs from PostgreSQL:
// deleting rows past their retention window, in batches, and recalibrating the
// derived user.state values.
//
// Each Delete* method returns the number of rows removed so the worker can keep
// sweeping until a pass comes back short. RecomputeDerivedState cannot use that
// stop rule (an unchanged row is still a candidate the next tick), so it advances
// by id instead.
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
	// PurgeDeletedUsers physically removes closed accounts whose deleted_at stamp
	// is older than before, writing a user_purge audit row per account inside the
	// same transaction. Returns the purged accounts with their COS avatar keys
	// (read before the cascade deleted the profile row) so the caller can remove
	// the objects outside the transaction.
	PurgeDeletedUsers(ctx context.Context, before, now time.Time, limit int) ([]repository.PurgedUser, error)
}

// Retention deletes expired OAuth metadata and aged-out audit logs, and keeps
// user.state calibrated against the derivation rule in internal/validate.
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
	// DeletedUserAge is the grace window between a soft close (DELETE
	// /admin/users/:id, which stamps deleted_at) and the physical purge that
	// removes the row and everything cascading from it. Zero disables the purge —
	// the sweep then never physically deletes, which is the pre-V023 behavior and
	// the brake to pull during an incident.
	DeletedUserAge time.Duration
	// AvatarStore removes COS objects for purged accounts. Nil skips object
	// cleanup (a deployment without STORAGE_* configured has no avatars to
	// remove); a failed delete is a logged orphan, never a failed purge.
	AvatarStore objectstore.ObjectStore
	Clock       auth.Clock
	// derivedFailures counts consecutive ticks whose derived-state recompute
	// errored without advancing. Past the threshold the cursor resets to the
	// table head: a persistent, position-stable error (bad row shape, planner
	// refusal) would otherwise wedge the sweep between the cursor and the end
	// forever — earlier rows never revisited, later rows never reached — with
	// only one Error log per tick as the symptom.
	derivedFailures int
	// DerivedStateCursor carries the user.state recompute position across ticks.
	// It is optional (nil restarts every tick, which is correct for any table that
	// fits in one sweep) and exists so a table larger than maxRetentionPasses x
	// BatchSize cannot starve its highest ids forever: the budget then advances
	// instead of restarting, and a completed sweep resets it to the head so the
	// next tick re-checks everything against the academic-year rule. Only the
	// advisory-lock holder touches it, from the single Run goroutine.
	DerivedStateCursor *int64
}

// Run sweeps on a ticker until ctx is canceled.
func (w *Retention) Run(ctx context.Context) error {
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
func (w *Retention) sweep(ctx context.Context) {
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
	// Closed accounts are purged after the token sweeps: their token metadata is
	// long revoked and swept by then, so the cascade deletes little beyond the
	// profile and identity rows. Disabled (age 0) is a deliberate off switch.
	if w.DeletedUserAge > 0 {
		w.purgeDeletedUsers(ctx, now)
	}
	// Derived user state is recalibrated in the same sweep, under the same
	// advisory lock, so two instances cannot interleave state writes. Unlike the
	// deletes above, an unchanged row still matches the candidate predicate, so
	// the cursor advances by id and a short batch ends the loop.
	cursor := int64(0)
	if w.DerivedStateCursor != nil {
		cursor = *w.DerivedStateCursor
	}
	for pass := 0; pass < maxRetentionPasses; pass++ {
		if ctx.Err() != nil {
			w.rememberDerivedStateCursor(cursor)
			return
		}
		next, recErr := w.Store.RecomputeDerivedState(ctx, cursor, now, w.batchSize())
		if recErr != nil {
			if ctx.Err() == nil {
				slog.Error("retention sweep derived state", "error", recErr)
				w.derivedFailures++
				if w.derivedFailures >= maxDerivedStateFailures {
					// Wedge breaker: three consecutive failing ticks at a stuck
					// position mean the cursor itself is the trap, so restart the
					// walk from the table head — the failing batch will error again
					// (visibly, every tick) instead of quietly starving every row
					// past it.
					slog.Error("retention derived-state cursor reset after repeated failures",
						"cursor", cursor, "failures", w.derivedFailures)
					w.rememberDerivedStateCursor(0)
					w.derivedFailures = 0
					return
				}
			}
			// Resume from where this tick got to rather than re-reading the same
			// head forever while a later table stays unreachable.
			w.rememberDerivedStateCursor(cursor)
			return
		}
		w.derivedFailures = 0
		if next == 0 {
			w.rememberDerivedStateCursor(0)
			return
		}
		cursor = next
	}
	// Hitting the pass cap means the table outgrew one tick's budget. Say so,
	// rather than letting a permanent backlog look like a clean sweep, and carry
	// the position so the next tick continues rather than restarts.
	slog.Warn("retention derived-state sweep truncated at pass cap",
		"cursor", cursor, "passes", maxRetentionPasses)
	w.rememberDerivedStateCursor(cursor)
}

// rememberDerivedStateCursor stores the sweep position for the next tick when a
// caller supplied a place to keep it.
func (w *Retention) rememberDerivedStateCursor(cursor int64) {
	if w.DerivedStateCursor != nil {
		*w.DerivedStateCursor = cursor
	}
}

// purgeDeletedUsers physically removes grace-expired closed accounts in batches,
// deleting each account's COS avatar outside the database transaction. A failed
// object delete is an orphan the storage lifecycle policy handles, not a reason
// to roll back a purge the audit row already recorded.
func (w Retention) purgeDeletedUsers(ctx context.Context, now time.Time) {
	cutoff := now.Add(-w.DeletedUserAge)
	batchSize := w.batchSize()
	var total int64
	for pass := 0; pass < maxRetentionPasses; pass++ {
		if ctx.Err() != nil {
			return
		}
		purged, err := w.Store.PurgeDeletedUsers(ctx, cutoff, now, batchSize)
		if err != nil {
			if ctx.Err() == nil {
				slog.Error("retention purge closed accounts", "deleted", total, "error", err)
			}
			return
		}
		for _, account := range purged {
			if account.Avatar == nil || w.AvatarStore == nil {
				continue
			}
			// Detached from ctx: the row is already gone, so an aborted shutdown-time
			// delete would strand the object with no row to rediscover it from. A
			// bounded window beats waiting out the shutdown.
			deleteCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			deleteErr := w.AvatarStore.Delete(deleteCtx, *account.Avatar)
			cancel()
			if deleteErr != nil {
				slog.Warn("retention purge orphaned avatar object", "user_id", account.ID, "error", deleteErr)
			}
		}
		total += int64(len(purged))
		if len(purged) < batchSize {
			if total > 0 {
				slog.Info("retention purge closed accounts", "deleted", total, "cutoff", cutoff)
			}
			return
		}
	}
	slog.Warn("retention purge truncated at pass cap",
		"deleted", total, "cutoff", cutoff, "passes", maxRetentionPasses)
}

// drain deletes in batches until a pass comes back short or the pass cap is hit.
func (w *Retention) drain(
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

func (w *Retention) validate() error {
	if w.Store == nil {
		return fmt.Errorf("retention worker requires a store")
	}
	if w.AuthorizationAge <= 0 || w.AccessTokenAge <= 0 || w.RefreshTokenAge <= 0 ||
		w.AuditLogAge <= 0 || w.AlumniRequestAge <= 0 {
		return fmt.Errorf("retention worker requires positive retention windows")
	}
	// DeletedUserAge is the one window that may be zero: zero is the documented
	// off switch for physical deletion, not a misconfiguration.
	if w.DeletedUserAge < 0 {
		return fmt.Errorf("retention worker deleted-user age must not be negative")
	}
	if w.Interval < 0 || w.BatchSize < 0 {
		return fmt.Errorf("retention worker interval and batch size must not be negative")
	}
	return nil
}

func (w *Retention) batchSize() int {
	if w.BatchSize > 0 {
		return w.BatchSize
	}
	return defaultRetentionBatchSize
}

func (w *Retention) now() time.Time {
	clock := w.Clock
	if clock == nil {
		clock = auth.SystemClock
	}
	return clock.Now().UTC()
}
