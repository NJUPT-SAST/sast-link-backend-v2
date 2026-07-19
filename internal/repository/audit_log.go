package repository

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
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
