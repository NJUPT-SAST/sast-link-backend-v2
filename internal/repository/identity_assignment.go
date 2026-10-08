package repository

import (
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// A single low-frequency assignment guard deliberately trades write parallelism
// for a simple lock order: assignment -> admin guard -> user/ticket -> identity.
// Every supported student-ID/login-email writer participates. READ COMMITTED
// rechecks after acquiring this lock observe the previous writer's commit.
// Imported duplicates remain readable; unrelated field edits do not reassign
// an identity. No existing migration or stored spelling is rewritten.
const identityAssignmentLockKey int64 = 0x534153544944

func lockIdentityAssignment(tx *gorm.DB) error {
	if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", identityAssignmentLockKey).Error; err != nil {
		return fmt.Errorf("lock identity assignment: %w", err)
	}
	return nil
}

func guardIdentityAssignment(tx *gorm.DB, userID int64, studentID, loginEmail *string) error {
	if studentID != nil {
		sid := strings.ToLower(strings.TrimSpace(*studentID))
		if sid != "" {
			var count int64
			if err := tx.Model(&model.User{}).Where(`id <> ? AND (lower(btrim(student_id)) = ? OR lower(btrim(login_email)) = ?)`, userID, sid, sid+"@njupt.edu.cn").Count(&count).Error; err != nil {
				return err
			}
			if count > 0 {
				return ErrStudentIDExists
			}
		}
	}
	if loginEmail != nil {
		email := strings.ToLower(strings.TrimSpace(*loginEmail))
		if prefix, lookup := validate.UnmatchedNjuptPrefix(email, ""); lookup {
			var count int64
			if err := tx.Model(&model.User{}).Where("id <> ? AND lower(btrim(student_id)) = ?", userID, prefix).Count(&count).Error; err != nil {
				return err
			}
			if count > 0 {
				return ErrStudentIDExists
			}
		}
	}
	return nil
}

func guardNewUserAssignment(tx *gorm.DB, user *model.User) error {
	if err := lockIdentityAssignment(tx); err != nil {
		return err
	}
	return guardIdentityAssignment(tx, 0, &user.StudentID, &user.LoginEmail)
}
