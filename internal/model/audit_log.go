package model

import "time"

// AuditLog persists an authentication or administration audit event. It is not an API DTO.
type AuditLog struct {
	ID         int64
	UserID     *int64
	Action     string
	Resource   string
	ResourceID *string
	Detail     JSONB   `gorm:"type:jsonb;default:(-)"`
	ClientIP   *string `gorm:"column:client_ip"`
	UserAgent  *string
	Success    *bool `gorm:"default:(-)"`
	ErrCode    *int
	CreatedAt  time.Time
}

// TableName returns the exact V001 table name for AuditLog.
func (AuditLog) TableName() string {
	return "audit_logs"
}
