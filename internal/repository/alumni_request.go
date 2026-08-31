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

// AlumniRequestFilter bounds a ticket listing. Status and Notified are
// tri-state: nil means "do not filter"; Notified filters on notified_at
// IS NULL / IS NOT NULL.
type AlumniRequestFilter struct {
	Status   *model.AlumniRequestStatus
	Notified *bool
	Keyword  string
	Limit    int
	Offset   int
}

// Create inserts a pending ticket. A collision on the pending-student unique
// index surfaces as a unique violation the caller classifies with
// DuplicateConstraint: one student ID holds at most one ticket awaiting review,
// while a rejected applicant may correct their details and resubmit.
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

// List returns a filtered page of tickets plus the total matching count. It
// mirrors ListAdminUsers: count on the same predicates without the window,
// ordered by id, over-cap limit refused rather than clamped.
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
		// ILIKE with both wildcards so a partial name or student ID matches; the
		// escape below keeps a literal % or _ from turning into a wildcard.
		pattern := "%" + escapeLikePattern(keyword) + "%"
		query = query.Where(
			"name ILIKE ? ESCAPE '\\' OR student_id ILIKE ? ESCAPE '\\' "+
				"OR login_email ILIKE ? ESCAPE '\\' OR personal_email ILIKE ? ESCAPE '\\'",
			pattern, pattern, pattern, pattern)
	}
	return query
}

// EmailHasPendingTicket reports whether a ticket awaiting review already carries
// the address as its personal or login email. The student-ID partial unique index
// cannot cover the email columns, so without this check the same personal email
// could accumulate several pending tickets under different student IDs — and the
// first approval would bind the address, leaving every other one stuck.
func (r *AlumniRequestRepository) EmailHasPendingTicket(ctx context.Context, email string) (bool, error) {
	if email == "" {
		return false, nil
	}
	var exists bool
	err := r.database.WithContext(ctx).Raw(`
		SELECT EXISTS (
			SELECT 1 FROM alumni_requests
			WHERE status = ? AND (personal_email = ? OR login_email = ?)
		)`, model.AlumniRequestStatusPending, email, email).Scan(&exists).Error
	if err != nil {
		return false, fmt.Errorf("check pending ticket email: %w", err)
	}
	return exists, nil
}

// AlumniProvision is what the service layer builds from a locked ticket: the rows
// to insert for the approved account. It is a callback rather than pre-built
// arguments because the password hash must be derived from the locked ticket
// inside the transaction: the transaction stays in the repository, the policy
// stays in the service.
type AlumniProvision func(*model.AlumniRequest) (*model.User, *model.Profile, *model.Identity, error)

// ApproveAlumniRequest locks a pending provision ticket, provisions the
// account, and writes the verdict in one transaction.
//
// All three writes commit together or none do: a committed account with a
// still-pending ticket would invite a second approval that collides with the
// student ID just inserted, and a committed verdict with no account would leave
// an alumnus holding an approval email for something that does not exist. The
// row lock (SELECT ... FOR UPDATE) is what makes a double-clicked approve button
// safe: the second transaction blocks, reads status = 'approved', and returns
// ErrStateConflict instead of provisioning again.
//
// Returns ErrNotFound for an unknown id, ErrStateConflict when the ticket
// already carries a verdict, ErrStudentIDExists under the folded comparison,
// and ErrInvalidArgument for a ticket whose intent is not provision — recovery
// has its own path in ApproveAlumniRequestRecover.
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
		if request.Intent != model.AlumniRequestIntentProvision {
			// The service dispatches on intent; this guard keeps a misdirected call
			// from provisioning beside a recovery target.
			return fmt.Errorf("%w: provision approval on a %s ticket", ErrInvalidArgument, request.Intent)
		}

		// The generic student-id unique constraint is case-sensitive, so a ticket
		// whose ID differs from an existing account's only by case (the import
		// produced both B24040525 and b24040525) would provision beside it. Check
		// the folded comparison here, under the ticket lock, before provisioning.
		var foldedExists bool
		if rawErr := transaction.Raw(
			`SELECT EXISTS (SELECT 1 FROM "user" WHERE lower(btrim(student_id)) = lower(btrim(?)))`,
			request.StudentID).Scan(&foldedExists).Error; rawErr != nil {
			return fmt.Errorf("check folded student id conflict: %w", rawErr)
		}
		if foldedExists {
			return ErrStudentIDExists
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

		if err := writeApprovalVerdict(transaction, requestID, user.ID, reviewerID, now); err != nil {
			return err
		}

		return transaction.Where("id = ?", requestID).Take(&approved).Error
	})
	if err != nil {
		return nil, err
	}
	return &approved, nil
}

// ApproveAlumniRequestRecover restores access to the account a recovery ticket's
// student ID already names: it binds PersonalEmail as that account's other_mail
// identity and records the verdict, all in one transaction. It does not
// provision anything — created_user_id records the recovered (existing) account.
//
// The user row is locked after the ticket row inside the same transaction, so a
// concurrent close cannot slip between the existence check and the binding.
// Returns ErrRecoverTargetMissing when the student ID stopped resolving to an
// account, ErrAccountClosed when that account is soft-deleted, and
// ErrLoginEmailMismatch when the locked row's login email disagrees with the
// ticket's — the same comparison the submission pre-check made, re-made against
// authoritative data the pre-check could have raced.
func (r *AlumniRequestRepository) ApproveAlumniRequestRecover(
	ctx context.Context,
	requestID int64,
	reviewerID int64,
	now time.Time,
) (*model.AlumniRequest, error) {
	if requestID <= 0 {
		return nil, fmt.Errorf("%w: request id must be positive", ErrInvalidArgument)
	}
	if reviewerID <= 0 {
		return nil, fmt.Errorf("%w: reviewer id must be positive", ErrInvalidArgument)
	}

	var approved model.AlumniRequest
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		request, err := lockPendingRequest(transaction, requestID)
		if err != nil {
			return err
		}
		if request.Intent != model.AlumniRequestIntentRecover {
			return fmt.Errorf("%w: recovery approval on a %s ticket", ErrInvalidArgument, request.Intent)
		}

		var target model.User
		err = transaction.
			Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("lower(btrim(student_id)) = lower(btrim(?))", request.StudentID).
			Take(&target).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrRecoverTargetMissing
		}
		if err != nil {
			return fmt.Errorf("lock recovery target: %w", err)
		}
		if target.State == model.UserStateDeleted {
			return ErrAccountClosed
		}
		if target.LoginEmail != request.LoginEmail {
			return ErrLoginEmailMismatch
		}

		// The V001 check_other_mail_limit trigger refuses a third binding with an
		// unnamed P0001 that DuplicateConstraint cannot classify, so the cap is
		// checked here, inside a transaction holding the row locks the insert also
		// needs — the count and the insert cannot race a concurrent bind.
		var bound int64
		if err := transaction.Model(&model.Identity{}).
			Where("user_id = ? AND provider = ?", target.ID, model.LoginMethodOtherMail).
			Count(&bound).Error; err != nil {
			return fmt.Errorf("count bound other_mail identities: %w", err)
		}
		if bound >= maxOtherMailBindings {
			return ErrIdentityLimitExceeded
		}
		// The V005 trigger refuses an address that is someone's login email and the
		// unique index refuses one already bound as other_mail, so a collision
		// surfaces as a unique violation the service classifies by constraint name.
		identity := &model.Identity{
			UserID:     target.ID,
			Provider:   model.LoginMethodOtherMail,
			ProviderID: request.PersonalEmail,
		}
		if err := transaction.Create(identity).Error; err != nil {
			return fmt.Errorf("bind recovery personal email: %w", err)
		}

		if err := writeApprovalVerdict(transaction, requestID, target.ID, reviewerID, now); err != nil {
			return err
		}

		return transaction.Where("id = ?", requestID).Take(&approved).Error
	})
	if err != nil {
		return nil, err
	}
	return &approved, nil
}

// writeApprovalVerdict records an approved ticket's outcome and its linkage to
// the account it acted on. Both approval paths share it; the row was locked by
// the caller, so a zero-row update can only be data drift, never a lost race.
func writeApprovalVerdict(
	transaction *gorm.DB,
	requestID int64,
	affectedUserID int64,
	reviewerID int64,
	now time.Time,
) error {
	result := transaction.Model(&model.AlumniRequest{}).
		Where("id = ?", requestID).
		Updates(map[string]any{
			"status":          model.AlumniRequestStatusApproved,
			"created_user_id": affectedUserID,
			"reviewed_by":     reviewerID,
			"reviewed_at":     now,
		})
	if result.Error != nil {
		return fmt.Errorf("approve alumni request: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("approve alumni request: %w", ErrNotFound)
	}
	return nil
}

// RejectAlumniRequest locks a pending ticket and records a rejection. It takes
// the same row lock as approval so two reviewers cannot both write a verdict,
// and the loser learns the ticket was already handled.
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

// ListUnnotifiedReviewed returns reviewed tickets whose result email was never
// attempted, oldest review first, capped at limit and skipping excludeIDs. A
// restart loses whatever the in-memory notification queue had not sent yet;
// notify_attempts = 0 identifies exactly those untouched jobs, and the partial
// index on (status <> pending, notified_at IS NULL) serves the query. The
// exclusion lets a re-queuing process walk a backlog longer than one batch
// without re-listing rows it already queued but has not started sending yet
// (the attempt counter only moves at send time).
func (r *AlumniRequestRepository) ListUnnotifiedReviewed(ctx context.Context, limit int, excludeIDs []int64) ([]model.AlumniRequest, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%w: limit must be positive", ErrInvalidArgument)
	}
	query := r.database.WithContext(ctx).
		Select("id", "personal_email", "name", "status", "intent", "reject_reason").
		Where("status <> ? AND notified_at IS NULL AND notify_attempts = 0",
			model.AlumniRequestStatusPending).
		Order("reviewed_at ASC")
	if len(excludeIDs) > 0 {
		query = query.Where("id NOT IN ?", excludeIDs)
	}
	rows := make([]model.AlumniRequest, 0, limit)
	err := query.Limit(limit).Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list unnotified reviewed alumni requests: %w", err)
	}
	return rows, nil
}

// MarkNotifyAttempt increments the delivery counter before a send is attempted,
// so a process killed mid-send leaves "tried, not confirmed" rather than
// discarding the evidence that a send was attempted.
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
