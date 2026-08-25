package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// AlumniRequestRepository persists alumni account-request tickets.
type AlumniRequestRepository struct {
	database *gorm.DB
}

// NewAlumniRequest constructs an alumni-request repository.
func NewAlumniRequest(database *gorm.DB) *AlumniRequestRepository {
	return &AlumniRequestRepository{database: database}
}

// AlumniRequestFilter bounds a ticket listing.
//
// Status and Notified are tri-state: nil means "do not filter". Notified filters
// on notified_at IS NULL / IS NOT NULL, which is the notification backlog the
// partial index idx_alumni_requests_pending_notification supports.
type AlumniRequestFilter struct {
	Status   *model.AlumniRequestStatus
	Notified *bool
	Keyword  string
	Limit    int
	Offset   int
}

// Create inserts a pending ticket.
//
// A collision on uq_alumni_requests_pending_student surfaces as a unique
// violation the caller classifies with DuplicateConstraint: one student ID may
// hold at most one ticket awaiting review, while a rejected applicant may correct
// their details and resubmit.
func (r *AlumniRequestRepository) Create(ctx context.Context, request *model.AlumniRequest) error {
	if request == nil {
		return fmt.Errorf("%w: request is nil", ErrInvalidArgument)
	}
	if err := r.database.WithContext(ctx).Create(request).Error; err != nil {
		return fmt.Errorf("create alumni request: %w", err)
	}
	return nil
}

// Get returns one ticket, or ErrNotFound.
func (r *AlumniRequestRepository) Get(ctx context.Context, requestID int64) (*model.AlumniRequest, error) {
	if requestID <= 0 {
		return nil, fmt.Errorf("%w: request id must be positive", ErrInvalidArgument)
	}
	var request model.AlumniRequest
	err := r.database.WithContext(ctx).Where("id = ?", requestID).Take(&request).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get alumni request: %w", err)
	}
	return &request, nil
}

// List returns a filtered page of tickets plus the total matching count.
//
// Mirrors ListAdminUsers: the count runs the same predicates without the window
// so a caller paging a filtered set sees a reachable total, ordering is by id
// because created_at is not unique enough to keep offset pages from overlapping,
// and an over-cap limit is refused rather than clamped so a caller cannot receive
// a differently sized page than it asked for.
func (r *AlumniRequestRepository) List(
	ctx context.Context,
	filter AlumniRequestFilter,
) ([]model.AlumniRequest, int64, error) {
	if filter.Limit <= 0 {
		return nil, 0, fmt.Errorf("%w: limit must be positive", ErrInvalidArgument)
	}
	if filter.Limit > validate.MaxPageSize {
		return nil, 0, fmt.Errorf("%w: limit must not exceed %d",
			ErrInvalidArgument, validate.MaxPageSize)
	}
	if filter.Offset < 0 {
		return nil, 0, fmt.Errorf("%w: offset must not be negative", ErrInvalidArgument)
	}

	var total int64
	if err := r.listQuery(ctx, filter).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count alumni requests: %w", err)
	}
	if total == 0 {
		return []model.AlumniRequest{}, 0, nil
	}

	rows := make([]model.AlumniRequest, 0, filter.Limit)
	err := r.listQuery(ctx, filter).
		Order("id DESC").
		Limit(filter.Limit).
		Offset(filter.Offset).
		Find(&rows).Error
	if err != nil {
		return nil, 0, fmt.Errorf("list alumni requests: %w", err)
	}
	return rows, total, nil
}

// listQuery builds the shared predicate set for List's count and page reads.
func (r *AlumniRequestRepository) listQuery(ctx context.Context, filter AlumniRequestFilter) *gorm.DB {
	query := r.database.WithContext(ctx).Model(&model.AlumniRequest{})
	if filter.Status != nil {
		query = query.Where("status = ?", *filter.Status)
	}
	if filter.Notified != nil {
		if *filter.Notified {
			query = query.Where("notified_at IS NOT NULL")
		} else {
			query = query.Where("notified_at IS NULL")
		}
	}
	if keyword := strings.TrimSpace(filter.Keyword); keyword != "" {
		// ILIKE with both wildcards: the reviewer is matching a name or a partial
		// student ID off a chat message, not running a prefix search. The escape
		// below keeps a literal % or _ in the keyword from turning into a wildcard.
		pattern := "%" + escapeLikePattern(keyword) + "%"
		query = query.Where(
			"name ILIKE ? ESCAPE '\\' OR student_id ILIKE ? ESCAPE '\\' "+
				"OR login_email ILIKE ? ESCAPE '\\' OR personal_email ILIKE ? ESCAPE '\\'",
			pattern, pattern, pattern, pattern)
	}
	return query
}

// AlumniProvision is what the service layer builds from a locked ticket: the rows
// to insert for the approved account.
//
// A callback rather than pre-built arguments because the mapping needs the ticket
// the transaction just locked, and the password hash must be derived from it
// inside the same call. This is the shape CreateRegistrationWithIdentity's
// TokenPairFactory uses for the same reason: the transaction stays in the
// repository, the policy stays in the service.
type AlumniProvision func(*model.AlumniRequest) (*model.User, *model.Profile, *model.Identity, error)

// ApproveAlumniRequest locks a pending ticket, provisions the account, and writes
// the verdict in one transaction.
//
// All three writes commit together or none do. Two failure modes make this
// necessary rather than merely tidy:
//
//   - A committed account with a still-pending ticket invites a second approval,
//     and the retry collides with the student ID the first one inserted - the
//     reviewer sees "学号已被占用" for an account the system itself just created.
//   - A committed verdict with no account leaves an alumnus holding an approval
//     email for an account that does not exist.
//
// SELECT ... FOR UPDATE is what makes a double-clicked approve button safe: the
// second transaction blocks until the first commits, then reads status =
// 'approved' and returns ErrStateConflict instead of provisioning again.
//
// Returns ErrNotFound for an unknown id and ErrStateConflict when the ticket
// already carries a verdict.
func (r *AlumniRequestRepository) ApproveAlumniRequest(
	ctx context.Context,
	requestID int64,
	reviewerID int64,
	now time.Time,
	provision AlumniProvision,
) (*model.AlumniRequest, error) {
	if requestID <= 0 {
		return nil, fmt.Errorf("%w: request id must be positive", ErrInvalidArgument)
	}
	if reviewerID <= 0 {
		return nil, fmt.Errorf("%w: reviewer id must be positive", ErrInvalidArgument)
	}
	if provision == nil {
		return nil, fmt.Errorf("%w: provision is nil", ErrInvalidArgument)
	}

	var approved model.AlumniRequest
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		request, err := lockPendingRequest(transaction, requestID)
		if err != nil {
			return err
		}

		user, profile, identity, err := provision(request)
		if err != nil {
			return err
		}
		if user == nil || profile == nil {
			return fmt.Errorf("%w: provision returned no user or profile", ErrInvalidArgument)
		}
		if err := createAdminUserInTransaction(transaction, user, profile, identity); err != nil {
			return err
		}

		result := transaction.Model(&model.AlumniRequest{}).
			Where("id = ?", requestID).
			Updates(map[string]any{
				"status":          model.AlumniRequestStatusApproved,
				"created_user_id": user.ID,
				"reviewed_by":     reviewerID,
				"reviewed_at":     now,
			})
		if result.Error != nil {
			return fmt.Errorf("approve alumni request: %w", result.Error)
		}
		if result.RowsAffected != 1 {
			// The row was locked above, so this cannot be a lost race. Fail rather
			// than commit a provisioned account whose ticket did not move.
			return fmt.Errorf("approve alumni request: %w", ErrNotFound)
		}

		return transaction.Where("id = ?", requestID).Take(&approved).Error
	})
	if err != nil {
		return nil, err
	}
	return &approved, nil
}

// RejectAlumniRequest locks a pending ticket and records a rejection.
//
// Takes the same row lock as approval for the same reason: two reviewers acting
// at once must not both write a verdict, and the loser must be told the ticket
// was already handled rather than silently overwriting the reason.
func (r *AlumniRequestRepository) RejectAlumniRequest(
	ctx context.Context,
	requestID int64,
	reviewerID int64,
	reason string,
	now time.Time,
) (*model.AlumniRequest, error) {
	if requestID <= 0 {
		return nil, fmt.Errorf("%w: request id must be positive", ErrInvalidArgument)
	}
	if reviewerID <= 0 {
		return nil, fmt.Errorf("%w: reviewer id must be positive", ErrInvalidArgument)
	}

	var rejected model.AlumniRequest
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if _, err := lockPendingRequest(transaction, requestID); err != nil {
			return err
		}
		result := transaction.Model(&model.AlumniRequest{}).
			Where("id = ?", requestID).
			Updates(map[string]any{
				"status":        model.AlumniRequestStatusRejected,
				"reject_reason": reason,
				"reviewed_by":   reviewerID,
				"reviewed_at":   now,
			})
		if result.Error != nil {
			return fmt.Errorf("reject alumni request: %w", result.Error)
		}
		if result.RowsAffected != 1 {
			return fmt.Errorf("reject alumni request: %w", ErrNotFound)
		}
		return transaction.Where("id = ?", requestID).Take(&rejected).Error
	})
	if err != nil {
		return nil, err
	}
	return &rejected, nil
}

// lockPendingRequest takes a row lock on a ticket and refuses one that already
// carries a verdict.
func lockPendingRequest(transaction *gorm.DB, requestID int64) (*model.AlumniRequest, error) {
	var request model.AlumniRequest
	err := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", requestID).
		Take(&request).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lock alumni request: %w", err)
	}
	if request.Status != model.AlumniRequestStatusPending {
		return nil, ErrStateConflict
	}
	return &request, nil
}

// MarkNotifyAttempt increments the delivery counter before a send is attempted.
//
// Counted before rather than after on purpose: a process killed mid-send leaves
// notify_attempts incremented and notified_at NULL, which reads as "tried, not
// confirmed delivered" - the truth. Incrementing afterwards would discard the
// evidence that anything was attempted.
func (r *AlumniRequestRepository) MarkNotifyAttempt(ctx context.Context, requestID int64) error {
	if requestID <= 0 {
		return fmt.Errorf("%w: request id must be positive", ErrInvalidArgument)
	}
	err := r.database.WithContext(ctx).Model(&model.AlumniRequest{}).
		Where("id = ?", requestID).
		UpdateColumn("notify_attempts", gorm.Expr("notify_attempts + 1")).Error
	if err != nil {
		return fmt.Errorf("mark alumni request notify attempt: %w", err)
	}
	return nil
}

// MarkNotified records that the result email was accepted by the SMTP server.
func (r *AlumniRequestRepository) MarkNotified(ctx context.Context, requestID int64, now time.Time) error {
	if requestID <= 0 {
		return fmt.Errorf("%w: request id must be positive", ErrInvalidArgument)
	}
	err := r.database.WithContext(ctx).Model(&model.AlumniRequest{}).
		Where("id = ?", requestID).
		UpdateColumn("notified_at", now).Error
	if err != nil {
		return fmt.Errorf("mark alumni request notified: %w", err)
	}
	return nil
}
