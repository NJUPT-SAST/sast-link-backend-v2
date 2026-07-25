package repository_test

import (
	"context"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func TestAuditLogRepositoryCreate(t *testing.T) {
	database := setupDatabase(t)
	auditLogRepository := repository.NewAuditLog(database)
	entry := &model.AuditLog{
		Action:   "login",
		Resource: "user",
		Detail:   model.JSONB(`{"provider":"password","success":true}`),
	}

	if err := auditLogRepository.Create(context.Background(), entry); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	var found model.AuditLog
	if err := database.First(&found, entry.ID).Error; err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if found.UserID != nil || found.Action != entry.Action || found.Resource != entry.Resource ||
		found.Success == nil || !*found.Success || entry.Success == nil || !*entry.Success ||
		!jsonEqual(found.Detail, entry.Detail) {
		t.Fatalf("audit log = %#v, want persisted default success and detail %s", found, entry.Detail)
	}

	falseValue := false
	failed := &model.AuditLog{Action: "login", Resource: "user", Success: &falseValue}
	if err := auditLogRepository.Create(context.Background(), failed); err != nil {
		t.Fatalf("Create(failed) error = %v", err)
	}
	var foundFailed model.AuditLog
	if err := database.First(&foundFailed, failed.ID).Error; err != nil {
		t.Fatalf("read failed audit log: %v", err)
	}
	if foundFailed.Success == nil || *foundFailed.Success {
		t.Fatalf("failed audit Success = %v, want false", foundFailed.Success)
	}

	invalid := &model.AuditLog{Action: strings.Repeat("a", 51), Resource: "user"}
	if err := auditLogRepository.Create(context.Background(), invalid); err == nil ||
		!strings.Contains(err.Error(), "create audit log") {
		t.Fatalf("Create(invalid) error = %v, want wrapped create audit log failure", err)
	}
}
