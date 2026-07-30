package repository

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// AuditLogRepository persists audit events.
type AuditLogRepository struct {
	database *gorm.DB
}

// NewAuditLog constructs an AuditLogRepository backed by database.
func NewAuditLog(database *gorm.DB) *AuditLogRepository {
	return &AuditLogRepository{database: database}
}

// Create persists an audit event.
func (r *AuditLogRepository) Create(ctx context.Context, entry *model.AuditLog) error {
	if err := r.database.WithContext(ctx).Create(entry).Error; err != nil {
		return fmt.Errorf("create audit log: %w", err)
	}
	return nil
}

// AuditLogFilter narrows an audit log query. Zero values mean "no constraint".
type AuditLogFilter struct {
	UserID   *int64
	Action   string
	Resource string
	Success  *bool
	// StartTime and EndTime bound created_at inclusively at the start and
	// exclusively at the end, so adjacent windows neither overlap nor skip an entry
	// written exactly on the boundary.
	StartTime *time.Time
	EndTime   *time.Time
	Limit     int
	Offset    int
}

// List returns a filtered page of audit entries plus the total matching count.
//
// Ordering is created_at DESC with id DESC as a tiebreak. created_at is not
// unique — a single request writes several entries within the same clock tick —
// and an offset scan over a non-deterministic order repeats and skips rows across
// pages.
func (r *AuditLogRepository) List(
	ctx context.Context,
	filter AuditLogFilter,
) ([]model.AuditLog, int64, error) {
	if filter.Limit <= 0 {
		return nil, 0, fmt.Errorf("%w: limit must be positive", ErrInvalidArgument)
	}
	if filter.Offset < 0 {
		return nil, 0, fmt.Errorf("%w: offset must not be negative", ErrInvalidArgument)
	}

	var total int64
	if err := r.auditLogQuery(ctx, filter).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count audit logs: %w", err)
	}
	if total == 0 {
		return []model.AuditLog{}, 0, nil
	}

	entries := make([]model.AuditLog, 0, validate.PreallocateRows(filter.Limit))
	err := r.auditLogQuery(ctx, filter).
		Order("created_at DESC, id DESC").
		Limit(filter.Limit).
		Offset(filter.Offset).
		Find(&entries).Error
	if err != nil {
		return nil, 0, fmt.Errorf("list audit logs: %w", err)
	}
	return entries, total, nil
}

// auditLogQuery builds the shared predicates of the list and its count.
func (r *AuditLogRepository) auditLogQuery(ctx context.Context, filter AuditLogFilter) *gorm.DB {
	query := r.database.WithContext(ctx).Model(&model.AuditLog{})
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.Action != "" {
		query = query.Where("action = ?", filter.Action)
	}
	if filter.Resource != "" {
		query = query.Where("resource = ?", filter.Resource)
	}
	if filter.Success != nil {
		query = query.Where("success = ?", *filter.Success)
	}
	if filter.StartTime != nil {
		query = query.Where("created_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("created_at < ?", *filter.EndTime)
	}
	return query
}
