package repository

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// retentionLockKey serializes retention sweeps across API instances. Every delete
// below is idempotent (DELETE WHERE already-dead), so the lock is not what makes
// them correct — it only stops two instances from paying for the same scan.
const retentionLockKey int64 = 0x5241_5445_4E54_4E00

// RetentionRepository deletes rows that have outlived their retention window.
type RetentionRepository struct {
	database *gorm.DB
	// mu guards lockConn, the connection pinned by TryLock. The advisory lock is
	// session-scoped, so it must be released on the connection that took it.
	mu       sync.Mutex
	lockConn *sql.Conn
}

// NewRetention constructs a retention repository.
func NewRetention(database *gorm.DB) *RetentionRepository {
	return &RetentionRepository{database: database}
}

// TryLock reports whether this instance won the right to run a retention sweep.
//
// pg_try_advisory_lock returns immediately rather than queueing: a sweep that
// loses the race should skip this tick, not repeat the same scan once the winner
// finishes. Missing a tick is harmless because the next one covers the same rows.
//
// The lock is session-scoped, and a pooled *gorm.DB hands out an arbitrary
// connection per statement — so releasing it through the pool could easily run
// pg_advisory_unlock on a connection that never held the lock. That returns false
// rather than erroring, and the real holder would stay locked until its connection
// happened to be recycled, blocking every later sweep on every instance. So the
// lock pins one connection for its whole lifetime and Unlock returns that same
// connection to the pool.
func (r *RetentionRepository) TryLock(ctx context.Context) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lockConn != nil {
		return false, fmt.Errorf("acquire retention lock: %w", ErrInvalidArgument)
	}
	pool, err := r.database.DB()
	if err != nil {
		return false, fmt.Errorf("acquire retention lock: %w", err)
	}
	conn, err := pool.Conn(ctx)
	if err != nil {
		return false, fmt.Errorf("acquire retention lock: %w", err)
	}
	var acquired bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", retentionLockKey).
		Scan(&acquired); err != nil {
		_ = conn.Close()
		return false, fmt.Errorf("acquire retention lock: %w", err)
	}
	if !acquired {
		_ = conn.Close()
		return false, nil
	}
	r.lockConn = conn
	return true, nil
}

// Unlock releases the retention advisory lock and frees its pinned connection.
func (r *RetentionRepository) Unlock(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	conn := r.lockConn
	if conn == nil {
		return nil
	}
	r.lockConn = nil
	var released bool
	err := conn.QueryRowContext(ctx, "SELECT pg_advisory_unlock($1)", retentionLockKey).Scan(&released)
	// Always return the connection: keeping it out of the pool after a failed
	// unlock would leak it, and closing it is also what drops a still-held
	// session lock server-side.
	if closeErr := conn.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("release retention lock: %w", err)
	}
	if !released {
		return fmt.Errorf("release retention lock: lock was not held")
	}
	return nil
}

// DeleteExpiredAuthorizations removes authorization codes that expired before
// cutoff, whether or not they were redeemed. A code is single-use and its replay
// defense lives in the family revocation performed at redemption time, so an
// expired row has no remaining authority to record.
func (r *RetentionRepository) DeleteExpiredAuthorizations(
	ctx context.Context,
	cutoff time.Time,
	batchSize int,
) (int64, error) {
	return r.deleteBatch(ctx, cutoff, batchSize, "expired authorizations",
		&model.OAuthAuthorization{}, "oauth_authorizations", "expires_at < ?", cutoff)
}

// DeleteExpiredAccessTokens removes access-token metadata that expired before
// cutoff.
//
// The auth middleware answers "no such JTI" with the same 401 it uses for a
// revoked token, so deleting a row whose JWT is still inside its exp would
// present an expired-but-valid token as revoked: the client receives
// CodeAccessTokenInvalid instead of CodeAccessTokenExpired and treats it as a
// forced logout rather than a cue to refresh. The caller's cutoff therefore
// trails expires_at by a wide margin; see RETENTION_ACCESS_TOKEN_AGE, which
// validation also refuses to set below JWT_ACCESS_TOKEN_EXPIRY.
func (r *RetentionRepository) DeleteExpiredAccessTokens(
	ctx context.Context,
	cutoff time.Time,
	batchSize int,
) (int64, error) {
	return r.deleteBatch(ctx, cutoff, batchSize, "expired access tokens",
		&model.OAuthAccessToken{}, "oauth_access_tokens", "expires_at < ?", cutoff)
}

// DeleteRevokedRefreshTokens removes refresh tokens that expired before cutoff,
// covering two shapes:
//
//   - rotated-away rows (revoked_at set, sequence > 0), the historic sweep;
//   - every row of a family that is entirely dead — no member is unrevoked and
//     still valid, so the family can never rotate again. That includes the
//     sequence-0 origin row a single login left behind when the user never came
//     back: it was never revoked, so the old `revoked_at IS NOT NULL` predicate
//     missed it and the table grew by one row per historical login.
//
// The origin row of a live family is still preserved: the refresh flow reads it to
// set an ID Token's auth_time, and a family that keeps rotating outlives the
// origin's own expires_at. Deleting it while the family lives makes the refresh
// flow revoke the family and return 500. "Live" means unrevoked and not yet
// expired, judged against cutoff so the sweep never races a valid token.
func (r *RetentionRepository) DeleteRevokedRefreshTokens(
	ctx context.Context,
	cutoff time.Time,
	batchSize int,
) (int64, error) {
	condition := `expires_at < ?
		AND (
			(revoked_at IS NOT NULL AND sequence > 0)
			OR NOT EXISTS (
				SELECT 1 FROM oauth_refresh_tokens live
				WHERE live.family_id = oauth_refresh_tokens.family_id
					AND live.revoked_at IS NULL
					AND live.expires_at > ?
			)
		)`
	return r.deleteBatch(ctx, cutoff, batchSize, "dead refresh tokens",
		&model.OAuthRefreshToken{}, "oauth_refresh_tokens", condition, cutoff, cutoff)
}

// DeleteExpiredAuditLogs removes audit entries created before cutoff.
func (r *RetentionRepository) DeleteExpiredAuditLogs(
	ctx context.Context,
	cutoff time.Time,
	batchSize int,
) (int64, error) {
	return r.deleteBatch(ctx, cutoff, batchSize, "expired audit logs",
		&model.AuditLog{}, "audit_logs", "created_at < ?", cutoff)
}

// deleteBatch deletes at most batchSize matching rows.
//
// The delete is restricted to a primary-key subquery rather than issuing a bare
// DELETE ... WHERE: an unbounded delete on a table that has gone uncleaned for
// months would hold row locks for the length of one statement, and this worker
// shares its connection pool with live request traffic. Returning the row count
// lets the caller keep sweeping until a pass comes back short.
func (r *RetentionRepository) deleteBatch(
	ctx context.Context,
	cutoff time.Time,
	batchSize int,
	operation string,
	target any,
	table string,
	condition string,
	args ...any,
) (int64, error) {
	if cutoff.IsZero() || batchSize <= 0 {
		return 0, fmt.Errorf("cleanup %s: %w", operation, ErrInvalidArgument)
	}
	subquery := r.database.WithContext(ctx).
		Table(table).
		Select("id").
		Where(condition, args...).
		Limit(batchSize)
	result := r.database.WithContext(ctx).
		Where("id IN (?)", subquery).
		Delete(target)
	if result.Error != nil {
		return 0, fmt.Errorf("cleanup %s: %w", operation, result.Error)
	}
	return result.RowsAffected, nil
}

// DeleteExpiredAlumniRequests removes account-request tickets reviewed before
// cutoff.
//
// Only approved and rejected tickets are swept, and the window is measured from
// reviewed_at rather than created_at. A pending ticket is never deleted however
// old it is: the three-day handling target is a statement in the UI, not a rule
// the backend enforces, and dropping an unreviewed application would lose
// someone's request rather than expire it. That is also why reviewed_at IS NOT
// NULL is part of the predicate and not merely implied by the status - a row with
// a verdict but no timestamp would otherwise be swept against a cutoff it has no
// value to compare with.
func (r *RetentionRepository) DeleteExpiredAlumniRequests(
	ctx context.Context,
	cutoff time.Time,
	batchSize int,
) (int64, error) {
	return r.deleteBatch(ctx, cutoff, batchSize, "reviewed alumni requests",
		&model.AlumniRequest{}, "alumni_requests",
		"status <> ? AND reviewed_at IS NOT NULL AND reviewed_at < ?",
		model.AlumniRequestStatusPending, cutoff)
}
