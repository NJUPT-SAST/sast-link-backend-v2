package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
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
// pg_try_advisory_lock returns immediately: a losing sweep skips this tick, and
// the next one covers the same rows. Because the advisory lock is session-scoped
// and a pooled DB hands out arbitrary connections per statement, the lock pins
// one connection for its whole lifetime and Unlock returns that same connection
// to the pool.
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
// cutoff, whether or not they were redeemed; replay defense lives in the
// redemption-time family revocation, so an expired row has no authority left.
func (r *RetentionRepository) DeleteExpiredAuthorizations(
	ctx context.Context,
	cutoff time.Time,
	batchSize int,
) (int64, error) {
	return r.deleteBatch(ctx, cutoff, batchSize, "expired authorizations",
		&model.OAuthAuthorization{}, "oauth_authorizations", "expires_at < ?", cutoff)
}

// DeleteExpiredAccessTokens removes access-token metadata that expired before
// cutoff. The middleware answers a missing JTI with the same 401 as a revoked
// token, so deleting a row still inside its exp would present an
// expired-but-valid token as revoked; the caller's cutoff therefore trails
// expires_at by a wide margin (RETENTION_ACCESS_TOKEN_AGE).
func (r *RetentionRepository) DeleteExpiredAccessTokens(
	ctx context.Context,
	cutoff time.Time,
	batchSize int,
) (int64, error) {
	return r.deleteBatch(ctx, cutoff, batchSize, "expired access tokens",
		&model.OAuthAccessToken{}, "oauth_access_tokens", "expires_at < ?", cutoff)
}

// DeleteRevokedRefreshTokens removes refresh tokens that expired before cutoff:
// rotated-away rows (revoked_at set, sequence > 0) and every row of a family
// that is entirely dead (no member unrevoked and still valid) — the only branch
// that removes a sequence-0 origin row left by a login the user never returned
// to.
//
// The origin row of a live family is preserved: the refresh flow reads it to
// date the family for the capability cap, and deleting it would make the refresh
// revoke the family and return 500. "Live" means unrevoked and not yet expired,
// judged against cutoff so the sweep never races a valid token.
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

// deleteBatch deletes at most batchSize matching rows via a primary-key
// subquery, so an uncleaned table cannot hold row locks for one unbounded
// statement; the returned count lets the caller sweep until a pass comes back
// short.
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
// cutoff. Only reviewed tickets are swept, measured from reviewed_at; a pending
// ticket is never deleted, however old, since the three-day target is a UI
// statement, not a backend rule. reviewed_at IS NOT NULL is part of the
// predicate so a verdict with no timestamp is not swept against a cutoff it has
// no value to compare with.
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

// RecomputeDerivedState recalibrates user.state against the derivation rule
// (internal/validate, the single source of truth — this SQL never re-derives).
// Candidates are unpinned (state_manual = FALSE) live accounts; rows whose
// derived value differs from the stored one are updated in place. The batch does
// not bump token_version and does not revoke sessions: state plays no part in
// authorization, so a state change is not a session cut.
//
// Rows are visited in id order past cursor, so repeated passes advance instead
// of rescanning the same head of the table — unlike a delete, an unchanged row
// still matches the candidate predicate, so a plain LIMIT would loop forever
// over the same first page. Returns the next cursor; 0 means the sweep reached
// the end.
func (r *RetentionRepository) RecomputeDerivedState(
	ctx context.Context,
	cursor int64,
	now time.Time,
	batchSize int,
) (int64, error) {
	if batchSize <= 0 {
		return 0, fmt.Errorf("recompute derived state: %w", ErrInvalidArgument)
	}
	var rows []model.User
	if err := r.database.WithContext(ctx).
		Select("id", "role", "student_id", "state").
		Where("state_manual = ? AND state <> ? AND id > ?",
			false, model.UserStateDeleted, cursor).
		Order("id").Limit(batchSize).
		Find(&rows).Error; err != nil {
		return 0, fmt.Errorf("recompute derived state: %w", err)
	}
	if len(rows) == 0 {
		return 0, nil
	}
	next := rows[len(rows)-1].ID
	// Collect divergent rows, then apply bounded multi-row statements: the academic
	// year boundary flips a whole cohort at once, and per-row UPDATEs turned one
	// tick into up to batchSize independent round trips. The per-row guards stay
	// in the WHERE clause, so a concurrent pin or closure still wins exactly as
	// the per-row form allowed.
	type divergence struct {
		id           int64
		derivedState model.UserState
	}
	divergent := make([]divergence, 0, len(rows))
	for _, row := range rows {
		derived, err := validate.DeriveState(row.Role, row.StudentID, now)
		if err != nil {
			// Defensive branch (student IDs are guaranteed parseable): leave the
			// row alone rather than guessing; the next pass skips it the same way.
			continue
		}
		if derived != row.State {
			divergent = append(divergent, divergence{id: row.ID, derivedState: derived})
		}
	}
	// 2 parameters per row plus 2 predicates; chunk well below the protocol cap.
	const derivedStateChunkSize = 1000
	for start := 0; start < len(divergent); start += derivedStateChunkSize {
		chunk := divergent[start:min(start+derivedStateChunkSize, len(divergent))]
		values := make([]string, 0, len(chunk))
		args := make([]any, 0, len(chunk)*2)
		for _, item := range chunk {
			args = append(args, item.id, string(item.derivedState))
			values = append(values, "(?::int8, ?::state_enum)")
		}
		if err := r.database.WithContext(ctx).
			Exec(fmt.Sprintf(
				`UPDATE "user" AS u SET state = v.target_state
				 FROM (VALUES %s) AS v(id, target_state)
				 WHERE u.id = v.id AND u.state_manual = ? AND u.state <> ?`,
				strings.Join(values, ", ")),
				append(args, false, model.UserStateDeleted)...).Error; err != nil {
			return 0, fmt.Errorf("recompute derived state: %w", err)
		}
	}
	// RowsAffected == 0 for a row means a concurrent writer pinned the row or
	// closed the account between the read and the update; both are between-state
	// changes the sweep must not fight, so the update is simply skipped.
	// A short batch means the cursor reached the end: report it as 0 so the
	// worker loop terminates without one extra no-op pass.
	if len(rows) < batchSize {
		return 0, nil
	}
	return next, nil
}

// PurgedUser is one physically deleted account, as the worker needs it: the id
// for logging, and the COS avatar key read off the profile row before the
// cascade removed it.
type PurgedUser struct {
	ID     int64
	Avatar *string
}

// PurgeDeletedUsers physically removes closed accounts whose deleted_at stamp is
// older than before, in one transaction per batch.
//
// The delete cascades profile, identities, token metadata, grants and badge
// (their FKs are ON DELETE CASCADE by design — the schema was laid out for this
// day), and sets NULL the audit_logs and alumni_requests references so history
// survives the account it names. A user_purge audit row is written per account
// inside the same transaction: the ledger that says "this person's data was
// destroyed at this moment" must not be separable from the destruction itself.
// user_id and actor_client_id are NULL on those rows — no subject, no OAuth
// credential, a background worker.
//
// Candidates are locked FOR UPDATE OF the user row with SKIP LOCKED, so a
// restore holding the lock removes the row from this batch (it is no longer
// closed once that transaction commits) instead of blocking the sweep. The
// delete re-states the full candidate predicate under the lock, so a row that
// changed shape mid-batch is left alone.
func (r *RetentionRepository) PurgeDeletedUsers(
	ctx context.Context,
	before time.Time,
	now time.Time,
	limit int,
) ([]PurgedUser, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("purge deleted users: %w", ErrInvalidArgument)
	}

	var purged []PurgedUser
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		rows := []PurgedUser{}
		if err := transaction.Raw(`
			SELECT "user".id, profile.avatar
			FROM "user"
			LEFT JOIN profile ON profile.user_id = "user".id
			WHERE "user".state = ? AND "user".deleted_at IS NOT NULL AND "user".deleted_at < ?
			ORDER BY "user".id
			LIMIT ?
			FOR UPDATE OF "user" SKIP LOCKED`,
			model.UserStateDeleted, before, limit).Scan(&rows).Error; err != nil {
			return fmt.Errorf("select closed accounts for purge: %w", err)
		}
		if len(rows) == 0 {
			return nil
		}

		ids := make([]int64, 0, len(rows))
		for _, row := range rows {
			ids = append(ids, row.ID)
		}
		result := transaction.Where(
			`id IN ? AND state = ? AND deleted_at IS NOT NULL AND deleted_at < ?`,
			ids, model.UserStateDeleted, before,
		).Delete(&model.User{})
		if result.Error != nil {
			return fmt.Errorf("purge closed accounts: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			// Every candidate changed shape between the lock and the delete (a
			// restore won). Nothing to ledger, nothing to hand back.
			return nil
		}

		purged = make([]PurgedUser, 0, len(rows))
		for _, row := range rows {
			// The audit row carries no profile data: the point is that the data is
			// gone, and the id plus the timestamp is the whole story a privacy
			// inquiry needs.
			id := row.ID
			resourceID := fmt.Sprintf("%d", id)
			success := true
			if err := transaction.Create(&model.AuditLog{
				Action:     "user_purge",
				Resource:   "user",
				ResourceID: &resourceID,
				Success:    &success,
				// The worker's clock, not time.Now() inside the transaction: the
				// ledger's "when" must answer to the same fixed clock the sweep
				// computed its cutoff from.
				CreatedAt: now,
			}).Error; err != nil {
				return fmt.Errorf("write user_purge audit row: %w", err)
			}
			purged = append(purged, row)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return purged, nil
}
