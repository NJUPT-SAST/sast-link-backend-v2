// Package domain defines core business entities, error codes, and audit types.
package domain

import (
	"time"

	"gorm.io/datatypes"
)

// AuditAction 审计操作类型.
type AuditAction string

// Audit actions for the audit log.
const (
	AuditActionRegister       AuditAction = "register"
	AuditActionLogin          AuditAction = "login"
	AuditActionLogout         AuditAction = "logout"
	AuditActionChangePassword AuditAction = "change_password"
	AuditActionResetPassword  AuditAction = "reset_password"
	AuditActionOAuthBind      AuditAction = "oauth_bind"
	AuditActionOAuthUnbind    AuditAction = "oauth_unbind"
	AuditActionUpdateProfile  AuditAction = "update_profile"
	AuditActionUploadAvatar   AuditAction = "upload_avatar"
	AuditActionAdminAction    AuditAction = "admin_action"
)

// AuditLog 审计日志表.
type AuditLog struct {
	ID         int64          `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	UserID     *int64         `gorm:"column:user_id;index" json:"user_id,omitempty"`
	Action     AuditAction    `gorm:"column:action;type:varchar(50);not null;index" json:"action"`
	Resource   string         `gorm:"column:resource;type:varchar(50);not null" json:"resource"`
	ResourceID *string        `gorm:"column:resource_id;type:varchar(255)" json:"resource_id,omitempty"`
	Detail     datatypes.JSON `gorm:"column:detail;type:jsonb;default:'{}'" json:"detail"`
	ClientIP   *string        `gorm:"column:client_ip;type:inet" json:"client_ip,omitempty"`
	UserAgent  *string        `gorm:"column:user_agent;type:text" json:"user_agent,omitempty"`
	Success    bool           `gorm:"column:success;not null;default:true" json:"success"`
	ErrCode    *int           `gorm:"column:err_code;type:int" json:"err_code,omitempty"`
	CreatedAt  time.Time      `gorm:"column:created_at;type:timestamptz;not null;default:now()" json:"created_at"`
}

// TableName 返回表名.
func (AuditLog) TableName() string {
	return "audit_logs"
}
